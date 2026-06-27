//! HTTP endpoint for rendering reports via the central registry.
//!
//! One route — `GET /reports/:code` — handles every plugin-declared
//! report. The framework mounts this route alongside plugin routes
//! in the host's `build_router`, behind the standard auth middleware,
//! so `Extension<AuthUser>` is guaranteed present when the handler
//! runs.
//!
//! Query contract:
//!
//! - `format=html|csv|json` (default: `html`)
//! - every other `?key=value` pair flows into [`ReportParams::query`]
//!   so plugin handlers can filter by date, entity id, etc.
//!
//! Responses:
//!
//! - **200 OK** + the rendered bytes with the handler's chosen
//!   Content-Type and a `Content-Disposition: inline; filename="…"`
//!   header (inline so browsers render HTML instead of force-
//!   downloading; downloaders get the suggested filename anyway).
//! - **400 Bad Request** — unknown format in the query string, or
//!   a known format the specific report does not declare as
//!   supported.
//! - **404 Not Found** — unknown report code.
//! - **500 Internal Server Error** — handler returned an error.
//!
//! Every successful render emits an [`AuditAction::BulkExport`]
//! event with the report code, format, byte count, and (if
//! available) query string — this is the compliance trail regulated
//! customers need for "who exported what".

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use tracing::{error, info, warn};

use vortex_security::{AuditAction, AuditEntry, AuditSeverity};

use crate::auth::AuthUser;
use crate::state::AppState;

use super::def::ReportParams;
use super::format::ReportFormat;

/// Build the report-endpoint router fragment. The host merges this
/// into `protected_routes` in `server.rs::build_router`.
pub fn reports_routes() -> Router<Arc<AppState>> {
    Router::new().route("/reports/{code}", get(render_report_handler))
}

/// Axum handler for `GET /reports/:code`.
async fn render_report_handler(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
    Query(mut query): Query<HashMap<String, String>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    // 1. Resolve the requested format. Default is HTML — the common
    //    "open in browser" path — but an explicit `?format=foo` must
    //    parse to a known variant.
    let requested_format = match query.remove("format") {
        Some(s) => match ReportFormat::from_str(&s) {
            Some(f) => f,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("unknown report format: {s}"),
                )
                    .into_response()
            }
        },
        None => ReportFormat::Html,
    };

    // 2. Look up the report definition in the registry.
    let def = match state.reports.get(&code) {
        Some(d) => d.clone(),
        None => {
            return (StatusCode::NOT_FOUND, format!("unknown report: {code}")).into_response();
        }
    };

    // 3. Validate that this report supports the requested format.
    //    (Declaring supported formats upfront lets the 400 happen
    //    before the handler body runs.)
    if !def.supports(requested_format) {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "report '{code}' does not support format '{}' — supported: {}",
                requested_format.as_str(),
                def.formats
                    .iter()
                    .map(|f| f.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
            .into_response();
    }

    // 4. Capture the query string for the audit payload (minus the
    //    format we already consumed). Handler receives the filtered
    //    copy as ReportParams.query.
    let audit_query = query.clone();
    let params = ReportParams {
        format: requested_format,
        query,
    };

    // 5. Invoke the handler. Any VortexError becomes a 500 with the
    //    error message in the body — handlers should not return
    //    errors for expected "empty result" cases, only for real
    //    failures.
    let output = match (def.handler)(state.clone(), params).await {
        Ok(o) => o,
        Err(e) => {
            error!(
                report_code = %code,
                format = requested_format.as_str(),
                error = %e,
                "report handler failed"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("report generation failed: {e}"),
            )
                .into_response();
        }
    };

    let byte_count = output.len();
    info!(
        report_code = %code,
        format = requested_format.as_str(),
        byte_count = byte_count as i64,
        user = %user.username,
        "report generated"
    );

    // 6. Emit the BulkExport audit event. Failure to write the audit
    //    entry is logged but does not fail the report render — the
    //    user should get their output even if the ledger is
    //    temporarily unhealthy, and the tracing log above still
    //    captures the event.
    let audit_entry = AuditEntry::new(AuditAction::BulkExport, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(user.username.clone())
        .with_session(user.session_id)
        .with_resource("report", code.clone())
        .with_resource_name(def.name.to_string())
        .with_details(serde_json::json!({
            "report_code": code,
            "report_name": def.name,
            "format": requested_format.as_str(),
            "byte_count": byte_count,
            "filename": output.filename,
            "query": audit_query,
        }));
    if let Err(e) = state.audit.log(audit_entry).await {
        warn!(
            report_code = %code,
            error = %e,
            "failed to write BulkExport audit entry for report render"
        );
    }

    // 7. Assemble the HTTP response.
    let mut headers = HeaderMap::new();
    if let Ok(ct) = HeaderValue::from_str(&output.content_type) {
        headers.insert(header::CONTENT_TYPE, ct);
    }
    // `inline` so browsers render HTML reports instead of forcing a
    // download; the filename hint is still honored by Save-As.
    if let Ok(disp) = HeaderValue::from_str(&format!("inline; filename=\"{}\"", output.filename)) {
        headers.insert(header::CONTENT_DISPOSITION, disp);
    }

    (StatusCode::OK, headers, output.bytes).into_response()
}
