//! Admin UI for the batch run engine ([`crate::batch`]).
//!
//! An operator surface over runs the engine executes: a run list, a per-run
//! progress + exception summary, the exception (fail-item) queue, and the retry
//! action that requeues failed items once their cause is fixed. It is the
//! human-facing half of the engine's exception API — [`crate::batch::list_exceptions`]
//! / [`crate::batch::retry_exceptions`].
//!
//! Mounted by the host in `server.rs::build_router` via [`admin_routes`],
//! alongside the other framework route fragments, behind the auth middleware.
//! Every page is admin-gated. Routes:
//!
//! - `GET  /batch/runs`                       — recent runs
//! - `GET  /batch/runs/{id}`                  — one run: progress + counts
//! - `GET  /batch/runs/{id}/exceptions`       — the fail-item queue
//! - `POST /batch/runs/{id}/retry`            — requeue + re-dispatch all failures
//! - `POST /batch/runs/{id}/items/{item}/retry` — retry a single failed item

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Router,
};
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::auth::{AuthUser, Db};
use crate::shell::render_app_shell;
use crate::sidebar::build_sidebar;
use crate::state::{AppState, DatabaseContext};
use crate::ui::{forbidden_page, format_time_ago, get_initials, html_escape};

/// Route fragment for the batch admin UI. Merged into `protected_routes`.
pub fn admin_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/batch/runs", get(runs_list))
        .route("/batch/runs/{id}", get(run_detail))
        .route("/batch/runs/{id}/exceptions", get(exceptions_page))
        .route("/batch/runs/{id}/retry", post(retry_all))
        .route("/batch/runs/{id}/items/{item_id}/retry", post(retry_one))
        .route("/batch/runs/{id}/pause", post(pause_run))
        .route("/batch/runs/{id}/resume", post(resume_run))
        .route("/batch/runs/{id}/cancel", post(cancel_run))
}

/// Wrap a page body in the standard app shell with the sidebar, marking the
/// "Batch Runs" nav entry active.
fn shell(state: &AppState, user: &AuthUser, db_ctx: &DatabaseContext, title: &str, body: &str) -> String {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar(
        "batch",
        display_name,
        &initials,
        &installed,
        user.is_admin(),
        &state.plugin_registry,
        &user.roles,
        &db_ctx.custom_apps_html,
    );
    render_app_shell(title, &sidebar, body)
}

/// Coloured daisyUI badge for a run status.
fn status_badge(status: &str) -> &'static str {
    match status {
        "completed" => r#"<span class="badge badge-success badge-sm">Completed</span>"#,
        "running" => r#"<span class="badge badge-info badge-sm">Running</span>"#,
        "paused" => r#"<span class="badge badge-warning badge-sm">Paused</span>"#,
        "pending" => r#"<span class="badge badge-ghost badge-sm">Pending</span>"#,
        "cancelled" => r#"<span class="badge badge-warning badge-sm">Cancelled</span>"#,
        "failed" => r#"<span class="badge badge-error badge-sm">Failed</span>"#,
        _ => r#"<span class="badge badge-ghost badge-sm">?</span>"#,
    }
}

// ─── GET /batch/runs ─────────────────────────────────────────────────────

async fn runs_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    if !user.is_admin() {
        return (axum::http::StatusCode::FORBIDDEN, Html(forbidden_page("Batch Runs"))).into_response();
    }

    let rows = sqlx::query(
        "SELECT id, run_kind, status, trial, total_items, processed_items, \
                succeeded_items, exception_items, created_at \
         FROM batch_run ORDER BY created_at DESC LIMIT 100",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: Uuid = row.get("id");
        let kind: String = row.get("run_kind");
        let status: String = row.get("status");
        let trial: bool = row.get("trial");
        let total: i32 = row.get("total_items");
        let processed: i32 = row.get("processed_items");
        let exceptions: i32 = row.get("exception_items");
        let created: chrono::DateTime<chrono::Utc> = row.get("created_at");

        let trial_badge = if trial {
            r#" <span class="badge badge-outline badge-xs">trial</span>"#
        } else {
            ""
        };
        let exc_cell = if exceptions > 0 {
            format!(r#"<span class="text-error font-semibold">{exceptions}</span>"#)
        } else {
            "0".to_string()
        };
        table_rows.push_str(&format!(
            r#"<tr class="hover"><td><a href="/batch/runs/{id}" class="link link-hover font-mono text-xs">{short}</a></td><td>{kind}{trial}</td><td>{status}</td><td>{processed}/{total}</td><td>{exc}</td><td>{created}</td></tr>"#,
            id = id,
            short = html_escape(&id.to_string()[..8]),
            kind = html_escape(&kind),
            trial = trial_badge,
            status = status_badge(&status),
            processed = processed,
            total = total,
            exc = exc_cell,
            created = format_time_ago(created),
        ));
    }
    if table_rows.is_empty() {
        table_rows = r#"<tr><td colspan="6" class="text-center opacity-60 py-8">No batch runs yet.</td></tr>"#.to_string();
    }

    let body = format!(
        r#"<div class="p-6 max-w-6xl mx-auto">
  <h1 class="text-2xl font-bold mb-1">Batch Runs</h1>
  <p class="opacity-60 mb-6 text-sm">Runs executed by the batch engine — progress, exceptions, and retry.</p>
  <div class="overflow-x-auto border border-base-300 rounded-lg">
    <table class="table table-sm">
      <thead><tr><th>Run</th><th>Kind</th><th>Status</th><th>Processed</th><th>Exceptions</th><th>Created</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>"#,
        rows = table_rows
    );

    Html(shell(&state, &user, &db_ctx, "Batch Runs", &body)).into_response()
}

// ─── GET /batch/runs/{id} ────────────────────────────────────────────────

async fn run_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<Uuid>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    if !user.is_admin() {
        return (axum::http::StatusCode::FORBIDDEN, Html(forbidden_page("Batch Runs"))).into_response();
    }

    let run = match crate::batch::get_run(&db, id).await {
        Ok(Some(r)) => r,
        Ok(None) => return (axum::http::StatusCode::NOT_FOUND, Html(shell(&state, &user, &db_ctx, "Batch Run", "<div class=\"p-6\">Run not found.</div>"))).into_response(),
        Err(e) => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };

    let pct = if run.total_items > 0 {
        (run.processed_items as f64 / run.total_items as f64 * 100.0).round() as i32
    } else {
        0
    };
    let trial_badge = if run.trial {
        r#" <span class="badge badge-outline badge-sm">trial</span>"#
    } else {
        ""
    };

    // Status-aware run controls: pause/cancel while active, resume while paused.
    let controls = match run.status.as_str() {
        "running" => format!(
            r#"<form method="POST" action="/batch/runs/{id}/pause" class="inline"><button class="btn btn-sm">Pause</button></form>
               <form method="POST" action="/batch/runs/{id}/cancel" class="inline"><button class="btn btn-sm btn-error btn-outline" onclick="return confirm('Cancel this run?')">Cancel</button></form>"#,
            id = id
        ),
        "paused" => format!(
            r#"<form method="POST" action="/batch/runs/{id}/resume" class="inline"><button class="btn btn-sm btn-primary">Resume</button></form>
               <form method="POST" action="/batch/runs/{id}/cancel" class="inline"><button class="btn btn-sm btn-error btn-outline" onclick="return confirm('Cancel this run?')">Cancel</button></form>"#,
            id = id
        ),
        "pending" => format!(
            r#"<form method="POST" action="/batch/runs/{id}/cancel" class="inline"><button class="btn btn-sm btn-error btn-outline">Cancel</button></form>"#,
            id = id
        ),
        _ => String::new(),
    };
    let controls_block = if controls.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="flex gap-2 mb-4">{controls}</div>"#)
    };

    let exceptions_block = if run.exception_items > 0 {
        format!(
            r#"<div class="alert alert-warning mt-6">
  <div class="flex-1">
    <span><strong>{n}</strong> item(s) failed and are in the exception queue.</span>
  </div>
  <a href="/batch/runs/{id}/exceptions" class="btn btn-sm">Review queue</a>
  <form method="POST" action="/batch/runs/{id}/retry" class="inline">
    <button class="btn btn-sm btn-primary" onclick="return confirm('Requeue and re-run all {n} failed items?')">Retry all</button>
  </form>
</div>"#,
            n = run.exception_items,
            id = id
        )
    } else {
        String::new()
    };

    let body = format!(
        r#"<div class="p-6 max-w-4xl mx-auto">
  <div class="flex items-center gap-3 mb-1">
    <a href="/batch/runs" class="btn btn-ghost btn-xs">&larr; Runs</a>
    <h1 class="text-2xl font-bold">{kind}{trial}</h1>
    {status}
  </div>
  <p class="opacity-60 mb-6 font-mono text-xs">{id}</p>

  <div class="stats stats-vertical sm:stats-horizontal border border-base-300 w-full mb-4">
    <div class="stat"><div class="stat-title">Total</div><div class="stat-value text-2xl">{total}</div></div>
    <div class="stat"><div class="stat-title">Processed</div><div class="stat-value text-2xl">{processed}</div></div>
    <div class="stat"><div class="stat-title">Succeeded</div><div class="stat-value text-2xl text-success">{succeeded}</div></div>
    <div class="stat"><div class="stat-title">Exceptions</div><div class="stat-value text-2xl text-error">{exceptions}</div></div>
  </div>

  <div class="mb-1 text-sm opacity-70">{pct}% processed</div>
  <progress class="progress progress-primary w-full mb-4" value="{processed}" max="{total_or_one}"></progress>

  {controls_block}
  {exceptions_block}
</div>"#,
        kind = html_escape(&run.run_kind),
        trial = trial_badge,
        status = status_badge(&run.status),
        id = id,
        total = run.total_items,
        processed = run.processed_items,
        succeeded = run.succeeded_items,
        exceptions = run.exception_items,
        pct = pct,
        total_or_one = run.total_items.max(1),
        controls_block = controls_block,
        exceptions_block = exceptions_block,
    );

    Html(shell(&state, &user, &db_ctx, "Batch Run", &body)).into_response()
}

// ─── GET /batch/runs/{id}/exceptions ─────────────────────────────────────

async fn exceptions_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<Uuid>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    if !user.is_admin() {
        return (axum::http::StatusCode::FORBIDDEN, Html(forbidden_page("Batch Runs"))).into_response();
    }

    let items = match crate::batch::list_exceptions(&db, id, 500, 0).await {
        Ok(i) => i,
        Err(e) => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };

    let mut rows = String::new();
    for it in &items {
        rows.push_str(&format!(
            r#"<tr class="hover"><td class="font-mono text-xs">{key}</td><td>{stage}</td><td class="text-error text-xs">{err}</td><td>{attempts}</td><td><form method="POST" action="/batch/runs/{id}/items/{item}/retry" class="inline"><button class="btn btn-xs btn-ghost">Retry</button></form></td></tr>"#,
            key = html_escape(&it.item_key),
            stage = html_escape(it.stage_failed.as_deref().unwrap_or("—")),
            err = html_escape(it.error_detail.as_deref().unwrap_or("")),
            attempts = it.attempts,
            id = id,
            item = it.item_id,
        ));
    }
    let body = if items.is_empty() {
        format!(
            r#"<div class="p-6 max-w-5xl mx-auto">
  <a href="/batch/runs/{id}" class="btn btn-ghost btn-xs mb-4">&larr; Run</a>
  <div class="alert alert-success">No exceptions — every item in this run succeeded.</div>
</div>"#,
            id = id
        )
    } else {
        format!(
            r#"<div class="p-6 max-w-5xl mx-auto">
  <div class="flex items-center justify-between mb-4">
    <a href="/batch/runs/{id}" class="btn btn-ghost btn-xs">&larr; Run</a>
    <form method="POST" action="/batch/runs/{id}/retry" class="inline">
      <button class="btn btn-sm btn-primary" onclick="return confirm('Requeue and re-run all failed items?')">Retry all</button>
    </form>
  </div>
  <h1 class="text-2xl font-bold mb-4">Exception queue</h1>
  <div class="overflow-x-auto border border-base-300 rounded-lg">
    <table class="table table-sm">
      <thead><tr><th>Item</th><th>Stage</th><th>Error</th><th>Attempts</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>"#,
            id = id,
            rows = rows
        )
    };

    Html(shell(&state, &user, &db_ctx, "Exception Queue", &body)).into_response()
}

// ─── POST retry ──────────────────────────────────────────────────────────

async fn retry_all(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<Uuid>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if !user.is_admin() {
        return (axum::http::StatusCode::FORBIDDEN, Html(forbidden_page("Batch Runs"))).into_response();
    }
    let dispatched = match crate::batch::retry_exceptions(&state, &db, id, None).await {
        Ok(n) => n,
        Err(e) => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    crate::audit_events::emit(
        &state,
        &user,
        "batch.run.retried",
        "batch_run",
        id.to_string(),
        serde_json::json!({ "scope": "all", "chunks_dispatched": dispatched }),
    )
    .await;
    Redirect::to(&format!("/batch/runs/{id}")).into_response()
}

async fn retry_one(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path((id, item_id)): Path<(Uuid, Uuid)>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if !user.is_admin() {
        return (axum::http::StatusCode::FORBIDDEN, Html(forbidden_page("Batch Runs"))).into_response();
    }
    if let Err(e) = crate::batch::retry_exceptions(&state, &db, id, Some(&[item_id])).await {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    crate::audit_events::emit(
        &state,
        &user,
        "batch.run.retried",
        "batch_run",
        id.to_string(),
        serde_json::json!({ "scope": "item", "item_id": item_id.to_string() }),
    )
    .await;
    Redirect::to(&format!("/batch/runs/{id}/exceptions")).into_response()
}

async fn pause_run(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<Uuid>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if !user.is_admin() {
        return (axum::http::StatusCode::FORBIDDEN, Html(forbidden_page("Batch Runs"))).into_response();
    }
    if let Err(e) = crate::batch::pause(&db, id).await {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    crate::audit_events::emit(&state, &user, "batch.run.paused", "batch_run", id.to_string(), serde_json::json!({})).await;
    Redirect::to(&format!("/batch/runs/{id}")).into_response()
}

async fn resume_run(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<Uuid>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if !user.is_admin() {
        return (axum::http::StatusCode::FORBIDDEN, Html(forbidden_page("Batch Runs"))).into_response();
    }
    if let Err(e) = crate::batch::resume(&state, &db, id).await {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    crate::audit_events::emit(&state, &user, "batch.run.resumed", "batch_run", id.to_string(), serde_json::json!({})).await;
    Redirect::to(&format!("/batch/runs/{id}")).into_response()
}

async fn cancel_run(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<Uuid>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if !user.is_admin() {
        return (axum::http::StatusCode::FORBIDDEN, Html(forbidden_page("Batch Runs"))).into_response();
    }
    if let Err(e) = crate::batch::cancel(&db, id).await {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    crate::audit_events::emit(&state, &user, "batch.run.cancelled", "batch_run", id.to_string(), serde_json::json!({})).await;
    Redirect::to(&format!("/batch/runs/{id}")).into_response()
}
