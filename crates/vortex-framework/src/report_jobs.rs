//! # Async report pipeline — queue → render → store → notify
//!
//! Heavy reports (multi-year GL, big exports) must not run inside an
//! HTTP request: the proxy times out at minutes, the browser hangs,
//! and a restart loses the work. This module runs them through the
//! durable job queue instead:
//!
//! 1. A handler calls [`enqueue_run`] — one `report_runs` row
//!    (tenant DB, status `queued`) + one `ir_job` (`report.render`).
//! 2. The job worker claims the run, renders it with the same
//!    `user_reports` engine the synchronous route uses, and writes
//!    the artifact to [`AppState::files`] under
//!    `reports/<run_id>.<ext>` in the tenant's namespace.
//! 3. The run row flips to `done` (or `failed` with the error), and
//!    the requester gets a best-effort `mail.send` notification.
//! 4. The user downloads from the "Generated Reports" inbox whenever
//!    they like; a retention sweep deletes old runs + blobs.
//!
//! Because the work is claimed from the central queue, any instance
//! pointed at the same primary DB participates — a dedicated
//! reporting server is a deployment choice, not a code change.

use serde_json::json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::jobs::{self, JobRegistry, NewJob};
use crate::state::AppState;
use crate::user_reports as ur;

pub const JOB_KIND: &str = "report.render";

/// Formats a run may request. CSV is tabular-only (enforced at render).
pub fn valid_format(f: &str) -> bool {
    matches!(f, "html" | "csv" | "pdf")
}

/// Days a finished run (row + artifact) is kept before the retention
/// sweep removes it. Override with `VORTEX_REPORT_RETENTION_DAYS`.
pub fn retention_days() -> i64 {
    std::env::var("VORTEX_REPORT_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(30)
}

/// Create a queued run and its job. `tenant_pool` is the tenant DB the
/// report (and the `report_runs` row) lives in; `jobs_pool` is the
/// primary DB that owns the central queue.
pub async fn enqueue_run(
    jobs_pool: &PgPool,
    tenant_pool: &PgPool,
    db_name: &str,
    def: &ur::ReportDef,
    format: &str,
    user_id: Uuid,
    username: &str,
) -> Result<Uuid, String> {
    if !valid_format(format) {
        return Err(format!("unsupported format {format:?}"));
    }
    if format == "csv" && def.report_type != "tabular" {
        return Err("CSV export is only available for tabular reports".into());
    }

    let run_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO report_runs
               (report_id, report_code, report_name, format, status, requested_by, requested_by_name)
           VALUES ($1, $2, $3, $4, 'queued', $5, $6)
           RETURNING id"#,
    )
    .bind(def.id)
    .bind(&def.code)
    .bind(&def.name)
    .bind(format)
    .bind(user_id)
    .bind(username)
    .fetch_one(tenant_pool)
    .await
    .map_err(|e| format!("could not record report run: {e}"))?;

    let job = NewJob::new(JOB_KIND, json!({ "run_id": run_id }))
        .for_db(db_name)
        .trace("report_run", &run_id.to_string())
        .max_attempts(2);
    if let Err(e) = jobs::enqueue(jobs_pool, job).await {
        let _ = sqlx::query(
            "UPDATE report_runs SET status = 'failed', error = $2, finished_at = NOW() WHERE id = $1",
        )
        .bind(run_id)
        .bind(format!("could not enqueue job: {e}"))
        .execute(tenant_pool)
        .await;
        return Err(format!("could not enqueue report job: {e}"));
    }
    Ok(run_id)
}

/// Register the `report.render` handler. Called from
/// [`jobs::register_core_handlers`].
pub fn register(reg: &mut JobRegistry) {
    reg.register(JOB_KIND, |ctx| async move { render_job(ctx).await });
}

async fn render_job(ctx: jobs::JobContext) -> Result<(), String> {
    let run_id = ctx
        .payload
        .get("run_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("report.render: missing run_id")?;
    let db_name = ctx
        .db_name
        .clone()
        .ok_or("report.render: job has no tenant db_name")?;
    let pool = ctx.pool().await;

    // Claim the run. `failed` is claimable so queue retries (and the
    // inbox Retry button) can re-render; a `running` row older than
    // 30 minutes is treated as abandoned by a dead worker.
    let claimed = sqlx::query(
        r#"UPDATE report_runs
           SET status = 'running', started_at = NOW(), error = NULL
           WHERE id = $1
             AND (status IN ('queued', 'failed')
                  OR (status = 'running' AND started_at < NOW() - INTERVAL '30 minutes'))
           RETURNING report_id, format, requested_by"#,
    )
    .bind(run_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| format!("claim run: {e}"))?;
    let Some(run) = claimed else {
        // Already done, or another worker owns it.
        return Ok(());
    };
    let report_id: Uuid = run.get("report_id");
    let format: String = run.get("format");
    let requested_by: Uuid = run.get("requested_by");

    match render_and_store(&ctx.state, &pool, &db_name, run_id, report_id, &format).await {
        Ok((store_key, size, mime)) => {
            sqlx::query(
                r#"UPDATE report_runs
                   SET status = 'done', store_key = $2, file_size = $3, mime = $4, finished_at = NOW()
                   WHERE id = $1"#,
            )
            .bind(run_id)
            .bind(&store_key)
            .bind(size)
            .bind(&mime)
            .execute(&pool)
            .await
            .map_err(|e| format!("finish run: {e}"))?;
            notify_requester(&ctx.state, &pool, &db_name, run_id, requested_by).await;
            Ok(())
        }
        Err(msg) => {
            let _ = sqlx::query(
                "UPDATE report_runs SET status = 'failed', error = $2, finished_at = NOW() WHERE id = $1",
            )
            .bind(run_id)
            .bind(&msg)
            .execute(&pool)
            .await;
            // Propagate so the queue applies retry/backoff/dead-letter.
            Err(msg)
        }
    }
}

/// Render the report to bytes and persist the artifact. Returns
/// `(store_key, size, mime)`.
async fn render_and_store(
    state: &AppState,
    pool: &PgPool,
    db_name: &str,
    run_id: Uuid,
    report_id: Uuid,
    format: &str,
) -> Result<(String, i64, String), String> {
    let def = ur::load(pool, report_id)
        .await
        .ok_or("report definition no longer exists")?;

    let (bytes, ext, mime): (Vec<u8>, &str, &str) = if def.report_type == "banded" {
        // Pixel-perfect reports render through the Report Studio engine. CSV is
        // n/a for positioned layout, so anything but PDF falls back to HTML.
        let report = crate::banded_report::load(pool, report_id).await?.ok_or("banded report no longer exists")?;
        let provided = std::collections::BTreeMap::new();
        if format == "pdf" {
            (crate::banded_report::render_to_pdf(pool, &report, &provided).await?, "pdf", "application/pdf")
        } else {
            (crate::banded_report::render_to_html(pool, &report, &provided).await?.into_bytes(), "html", "text/html; charset=utf-8")
        }
    } else if format == "csv" {
        let res = ur::run_tabular(pool, &def).await?;
        (ur::render_tabular_csv(&res), "csv", "text/csv")
    } else {
        let inner = if def.report_type == "template" {
            let records = ur::fetch_template_records(pool, &def).await?;
            let mut globals = std::collections::BTreeMap::new();
            globals.insert("report_name".to_string(), def.name.clone());
            globals.insert(
                "generated_at".to_string(),
                chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string(),
            );
            globals.insert("count".to_string(), records.len().to_string());
            ur::render_template(def.template.as_deref().unwrap_or(""), &records, &globals)
        } else {
            let res = ur::run_tabular(pool, &def).await?;
            ur::render_tabular_html(&def, &res)
        };
        let page = artifact_page(&def, &inner);
        match format {
            "pdf" => {
                let opts = crate::pdf::PdfOptions {
                    landscape: def.orientation == "landscape",
                    paper: crate::pdf::Paper::parse(&def.paper_size),
                    print_background: true,
                    margin_in: 0.4,
                    ..Default::default()
                };
                let bytes = crate::pdf::html_to_pdf(&page, &opts)
                    .await
                    .map_err(|e| format!("PDF render failed: {e}"))?;
                (bytes, "pdf", "application/pdf")
            }
            _ => (page.into_bytes(), "html", "text/html; charset=utf-8"),
        }
    };

    let store_key = format!("reports/{run_id}.{ext}");
    let size = bytes.len() as i64;
    state
        .files
        .put(db_name, &store_key, &bytes, Some(mime))
        .await
        .map_err(|e| format!("could not store artifact: {e}"))?;
    Ok((store_key, size, mime.to_string()))
}

/// Self-contained artifact page: report content + inline print CSS,
/// no toolbar or app chrome — this is the file a user keeps.
fn artifact_page(def: &ur::ReportDef, inner: &str) -> String {
    let page_css = if def.orientation == "landscape" {
        "@page { size: landscape; }"
    } else {
        "@page { size: portrait; }"
    };
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{}</title>\
         <style>{}\n{}</style></head><body class=\"report\">{}</body></html>",
        crate::ui::html_escape(&def.name),
        ur::REPORT_CSS,
        page_css,
        inner,
    )
}

/// Best-effort "your report is ready" email via the mail.send job.
/// Silently does nothing when the user has no email or SMTP is not
/// configured — the inbox page is the source of truth.
async fn notify_requester(
    state: &AppState,
    tenant_pool: &PgPool,
    db_name: &str,
    run_id: Uuid,
    requested_by: Uuid,
) {
    let email: Option<String> =
        sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND active = true")
            .bind(requested_by)
            .fetch_optional(tenant_pool)
            .await
            .ok()
            .flatten()
            .flatten();
    let Some(to) = email.filter(|e| !e.is_empty()) else {
        return;
    };
    let name: Option<String> =
        sqlx::query_scalar("SELECT report_name FROM report_runs WHERE id = $1")
            .bind(run_id)
            .fetch_optional(tenant_pool)
            .await
            .ok()
            .flatten();
    let name = name.unwrap_or_else(|| "Report".into());
    let job = NewJob::new(
        "mail.send",
        json!({
            "to": to,
            "subject": format!("Report ready: {name}"),
            "text": format!(
                "Your report \"{name}\" has finished generating.\n\n\
                 Download it in Vortex under Reports \u{25b8} Generated Reports."
            ),
            "context": "report_ready",
        }),
    )
    .for_db(db_name);
    if let Err(e) = jobs::enqueue(&state.db, job).await {
        tracing::warn!(error = %e, "could not enqueue report-ready notification");
    }
}

/// Retention sweep for one tenant: delete runs older than the window,
/// blobs first. Returns how many runs were removed.
pub async fn cleanup_tenant(state: &AppState, tenant_pool: &PgPool, db_name: &str) -> u64 {
    let days = retention_days();
    let old: Vec<(Uuid, Option<String>)> = match sqlx::query_as(
        "SELECT id, store_key FROM report_runs \
         WHERE created_at < NOW() - make_interval(days => $1) \
           AND status IN ('done', 'failed')",
    )
    .bind(days as i32)
    .fetch_all(tenant_pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, %db_name, "report retention: query failed");
            return 0;
        }
    };

    let mut removed = 0u64;
    for (id, store_key) in old {
        if let Some(key) = &store_key {
            if let Err(e) = state.files.delete(db_name, key).await {
                tracing::warn!(error = %e, %key, "report retention: blob delete failed, keeping row");
                continue;
            }
        }
        match sqlx::query("DELETE FROM report_runs WHERE id = $1")
            .bind(id)
            .execute(tenant_pool)
            .await
        {
            Ok(_) => removed += 1,
            Err(e) => tracing::warn!(error = %e, "report retention: row delete failed"),
        }
    }
    removed
}
