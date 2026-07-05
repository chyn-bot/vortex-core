//! e-Invoice UI — queue page, per-document actions (export / submit /
//! retry / cancel), and MyInvois settings.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use crate::einvois::{flow, jobs};
use crate::handlers::{page_shell, render_sidebar};

pub fn einvoice_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounting/einvoice", get(queue_page))
        .route("/accounting/einvoice/settings", get(edit_einvoice_settings))
        .route("/accounting/einvoice/settings/{id}", post(save_einvoice_settings))
        .route("/accounting/einvoice/{move_id}/export", get(export_action))
        .route("/accounting/einvoice/{move_id}/submit", post(submit_action))
        .route("/accounting/einvoice/{move_id}/cancel", post(cancel_action))
        .route("/accounting/einvoice/sync-codes", post(sync_codes_action))
}

fn status_badge(status: &str) -> &'static str {
    match status {
        "valid" => "badge-success",
        "invalid" => "badge-error",
        "submitted" => "badge-info",
        "exported" => "badge-accent",
        "cancelled" => "badge-neutral",
        _ => "badge-ghost",
    }
}

/// Compact status widget for the document detail page.
pub async fn einvoice_widget(db: &vortex_plugin_sdk::sqlx::PgPool, move_id: Uuid) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT status, lhdn_uuid, validation_link, error_json FROM acc_einvoice WHERE move_id = $1",
    )
    .bind(move_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    let Some(r) = row else {
        return String::new();
    };
    let status: String = r.get("status");
    let uuid: Option<String> = r.get("lhdn_uuid");
    let link: Option<String> = r.get("validation_link");
    let err: Option<vortex_plugin_sdk::serde_json::Value> = r.try_get("error_json").ok().flatten();

    let mut actions = String::new();
    match status.as_str() {
        "ready" | "exported" | "invalid" => {
            actions.push_str(&format!(
                r#"<a href="/accounting/einvoice/{move_id}/export" class="btn btn-xs btn-outline">Export XML</a>
                   <form method="post" action="/accounting/einvoice/{move_id}/submit" class="inline"><button class="btn btn-xs btn-primary">Submit to LHDN</button></form>"#,
            ));
        }
        "valid" => {
            actions.push_str(&format!(
                r#"<form method="post" action="/accounting/einvoice/{move_id}/cancel" class="inline"><button class="btn btn-xs btn-outline btn-error" onclick="return confirm('Cancel this e-invoice with LHDN? Only possible within 72 hours.')">Cancel e-invoice</button></form>"#,
            ));
        }
        _ => {}
    }
    let link_html = link
        .map(|l| format!(r#"<a href="{}" target="_blank" class="link link-primary text-xs">validation link</a>"#, esc(&l)))
        .unwrap_or_default();
    let err_html = err
        .map(|e| {
            let msg = e
                .get("message")
                .and_then(|m| m.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| e.to_string());
            format!(
                r#"<div class="text-error text-xs mt-1 max-w-xl" title="{t}">⚠ {t}</div>"#,
                t = esc(&msg)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
        <div class="flex items-center gap-3 flex-wrap">
        <span class="font-semibold">e-Invoice</span>
        <span class="badge {badge}">{status}</span>
        <code class="text-xs">{uuid}</code>{link_html}{actions}
        </div>{err_html}</div></div>"#,
        badge = status_badge(&status),
        status = esc(&status),
        uuid = esc(uuid.as_deref().unwrap_or("")),
    )
}

async fn queue_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let filter = q.get("status").map(String::as_str).unwrap_or("");
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT e.move_id, e.status, e.doc_type_code, e.lhdn_uuid, e.submitted_at, \
                m.number, m.invoice_date, m.total_amount, c.name AS partner \
         FROM acc_einvoice e \
         JOIN acc_move m ON m.id = e.move_id \
         LEFT JOIN contacts c ON c.id = m.partner_id \
         WHERE ($1 = '' OR e.status = $1) \
         ORDER BY e.created_at DESC LIMIT 200",
    )
    .bind(filter)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let esc = vortex_plugin_sdk::framework::html_escape;
    let mut trs = String::new();
    for r in &rows {
        let mid: Uuid = r.get("move_id");
        let st: String = r.get("status");
        trs.push_str(&format!(
            "<tr class=\"hover cursor-pointer\" onclick=\"location='/accounting/documents/{mid}'\">\
             <td>{}</td><td>{}</td><td>{}</td><td class=\"text-right\">{}</td>\
             <td><span class=\"badge badge-sm {}\">{}</span></td><td><code class=\"text-xs\">{}</code></td></tr>",
            esc(r.get::<Option<String>, _>("number").as_deref().unwrap_or("/")),
            esc(r.get::<Option<String>, _>("partner").as_deref().unwrap_or("—")),
            r.get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("invoice_date")
                .map(|d| d.to_string())
                .unwrap_or_default(),
            r.get::<vortex_plugin_sdk::rust_decimal::Decimal, _>("total_amount").round_dp(2),
            status_badge(&st),
            esc(&st),
            esc(r.get::<Option<String>, _>("lhdn_uuid").as_deref().unwrap_or("")),
        ));
    }
    if trs.is_empty() {
        trs = "<tr><td colspan=\"6\" class=\"text-center opacity-60 py-6\">No e-invoices yet — they appear when customer documents post.</td></tr>".into();
    }
    let tabs: String = ["", "ready", "submitted", "valid", "invalid", "cancelled"]
        .iter()
        .map(|s| {
            let label = if s.is_empty() { "all" } else { s };
            let active = if *s == filter { "tab-active" } else { "" };
            format!(r#"<a class="tab {active}" href="/accounting/einvoice?status={s}">{label}</a>"#)
        })
        .collect();
    let content = format!(
        r##"<div class="flex justify-between items-start mb-4 gap-4">
        <div><h1 class="text-2xl font-bold">e-Invoice Queue (LHDN)</h1>
        <p class="text-sm opacity-60 mt-1 max-w-2xl">Submission monitor for MyInvois — every customer invoice lands here when posted. Submit or cancel from the invoice itself; this page is for watching statuses and retrying failures.</p></div>
        <div class="flex gap-2">
        <form method="post" action="/accounting/einvoice/sync-codes" class="inline"><button class="btn btn-sm btn-ghost">Sync LHDN codes</button></form>
        <a href="/accounting/einvoice/settings" class="btn btn-sm btn-outline">Settings</a></div></div>
        <div class="tabs tabs-boxed mb-4 w-fit">{tabs}</div>
        <div class="card bg-base-100 shadow"><div class="card-body p-4 overflow-x-auto">
        <table class="table table-sm"><thead><tr><th>Number</th><th>Partner</th><th>Date</th>
        <th class="text-right">Total</th><th>Status</th><th>LHDN UUID</th></tr></thead>
        <tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "e-Invoice Queue", &content)).into_response()
}

fn settings_form() -> FormConfig {
    FormConfig::new("MyInvois Settings", "acc_einvoice_settings", "/accounting/einvoice/settings")
        .field(FormField::select("mode", "Mode", &[
            ("portal", "Portal — generate XML, upload manually"),
            ("api", "API — submit directly to LHDN"),
        ]).required())
        .field(FormField::select("environment", "Environment", &[
            ("sandbox", "Sandbox (preprod)"),
            ("production", "Production"),
        ]).required())
        .field(FormField::text("client_id", "Client ID"))
        .field(FormField::checkbox("auto_submit", "Submit automatically on posting"))
        .field(FormField::many2one("consolidated_partner_id", "Consolidated B2C partner", "contacts")
            .help("Partner representing General Public for monthly consolidation"))
}

async fn edit_einvoice_settings(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let id: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_einvoice_settings ORDER BY company_id NULLS LAST LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(id) = id else {
        return (StatusCode::NOT_FOUND, "No e-invoice settings row").into_response();
    };
    let values = match load_record(&db, &settings_form(), id).await {
        Ok(Some(v)) => v,
        _ => return (StatusCode::NOT_FOUND, "No e-invoice settings row").into_response(),
    };
    let has_secret: bool = vortex_plugin_sdk::sqlx::query_scalar::<_, bool>(
        "SELECT client_secret_enc IS NOT NULL FROM acc_einvoice_settings WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap_or(false);
    let form = render_form(
        &db, &settings_form(), FormMode::Edit, Some(&id.to_string()), &values, &[],
    )
    .await;
    // The secret is write-only: entered through a dedicated field,
    // encrypted at rest, never rendered back.
    let secret_note = if has_secret { "a secret is stored — enter a new value to replace it" } else { "no secret stored yet" };
    let secret_html = format!(
        r#"<div class="card bg-base-100 shadow mt-4 max-w-2xl"><div class="card-body">
        <label class="form-control"><div class="label"><span class="label-text">Client Secret</span>
        <span class="label-text-alt opacity-60">{secret_note}</span></div>
        <input type="password" name="client_secret" form="einv-secret" class="input input-bordered w-full" autocomplete="new-password"/></label>
        <form id="einv-secret" method="post" action="/accounting/einvoice/settings/{id}"><input type="hidden" name="__secret_only" value="1"/>
        <div class="card-actions justify-end mt-2"><button class="btn btn-primary btn-sm">Save Secret</button></div></form>
        </div></div>"#,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "MyInvois Settings", &format!("{form}{secret_html}"))).into_response()
}

async fn save_einvoice_settings(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let secret_only = pairs.iter().any(|(k, _)| k == "__secret_only");
    if secret_only {
        let secret = pairs
            .iter()
            .rev()
            .find(|(k, _)| k == "client_secret")
            .map(|(_, v)| v.trim())
            .filter(|s| !s.is_empty());
        if let Some(secret) = secret {
            let key = vortex_plugin_sdk::security::crypto::master_key();
            match vortex_plugin_sdk::security::crypto::encrypt_str(secret, &key) {
                Ok(enc) => {
                    if let Err(e) = vortex_plugin_sdk::sqlx::query(
                        "UPDATE acc_einvoice_settings SET client_secret_enc = $2 WHERE id = $1",
                    )
                    .bind(id)
                    .bind(enc)
                    .execute(&db)
                    .await
                    {
                        error!("secret save failed: {e}");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response();
                    }
                    audit_einvoice(&state, &user, &db_ctx, id, "settings_secret_updated").await;
                }
                Err(e) => {
                    error!("secret encryption failed: {e} — is VORTEX_SECRET_KEY set?");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Encryption failed").into_response();
                }
            }
        }
        return Redirect::to("/accounting/einvoice/settings").into_response();
    }

    match execute_form_save(&db, &settings_form(), &pairs, Some(id)).await {
        Ok(SaveOutcome::Saved(_)) => {
            audit_einvoice(&state, &user, &db_ctx, id, "settings_updated").await;
            Redirect::to("/accounting/einvoice/settings").into_response()
        }
        Ok(SaveOutcome::Invalid { values, errors }) => {
            let form = render_form(
                &db, &settings_form(), FormMode::Edit, Some(&id.to_string()), &values, &errors,
            )
            .await;
            let sidebar = render_sidebar(&state, &user, &db_ctx);
            Html(page_shell(&sidebar, "MyInvois Settings", &form)).into_response()
        }
        Err(e) => {
            error!("einvoice settings save failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response()
        }
    }
}

async fn export_action(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(move_id): Path<Uuid>,
) -> Response {
    match flow::export_xml(&state, &db, &db_ctx.db_name, move_id).await {
        Ok((filename, xml)) => {
            audit_einvoice(&state, &user, &db_ctx, move_id, "exported").await;
            (
                StatusCode::OK,
                [
                    (vortex_plugin_sdk::axum::http::header::CONTENT_TYPE, "application/xml".to_string()),
                    (
                        vortex_plugin_sdk::axum::http::header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{filename}\""),
                    ),
                ],
                xml,
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!(
                "<p>Cannot export: {}</p>",
                vortex_plugin_sdk::framework::html_escape(&e.to_string())
            )),
        )
            .into_response(),
    }
}

async fn submit_action(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(move_id): Path<Uuid>,
) -> Response {
    let settings = match flow::settings(&db).await {
        Ok(s) => s,
        Err(e) => {
            error!("settings load failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Settings unavailable").into_response();
        }
    };
    let back = format!("/accounting/documents/{move_id}");
    if settings.mode != "api" {
        return flash_redirect(
            &back,
            FlashKind::Error,
            "Not submitted — API mode is off. Enable it in e-Invoice Settings, or use Export XML for the portal.",
        );
    }
    match jobs::enqueue_submit(&state.db, &db_ctx.db_name, move_id).await {
        Ok(()) => {
            audit_einvoice(&state, &user, &db_ctx, move_id, "submit_enqueued").await;
            flash_redirect(
                &back,
                FlashKind::Success,
                "Queued for LHDN submission — the status on this page updates automatically; refresh in a moment. Failures will show here in red.",
            )
        }
        Err(e) => {
            error!("submit enqueue failed: {e}");
            flash_redirect(
                &back,
                FlashKind::Error,
                "Not submitted — the job queue rejected the request. Check the server logs.",
            )
        }
    }
}

async fn cancel_action(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(move_id): Path<Uuid>,
) -> Response {
    let settings = match flow::settings(&db).await {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Settings unavailable").into_response(),
    };
    let api = match (settings.client_id.clone(), settings.client_secret.clone()) {
        (Some(id), Some(secret)) => {
            match crate::einvois::client::LhdnClient::new(settings.production, id, secret) {
                Ok(c) => c,
                Err(e) => {
                    error!("client build failed: {e}");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Client unavailable").into_response();
                }
            }
        }
        _ => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Html("<p>API credentials not configured.</p>".to_string()),
            )
                .into_response()
        }
    };
    match flow::cancel_via_api(&db, move_id, "Cancelled by issuer", &api).await {
        Ok(()) => {
            audit_einvoice(&state, &user, &db_ctx, move_id, "cancelled").await;
            flash_redirect(
                &format!("/accounting/documents/{move_id}"),
                FlashKind::Success,
                "e-Invoice cancelled with LHDN.",
            )
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!(
                "<p>Cannot cancel: {}</p>",
                vortex_plugin_sdk::framework::html_escape(&e)
            )),
        )
            .into_response(),
    }
}

async fn sync_codes_action(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    match vortex_plugin_sdk::framework::jobs::enqueue(
        &state.db,
        vortex_plugin_sdk::prelude::NewJob::new(jobs::KIND_SYNC_CODES, json!({}))
            .for_db(&db_ctx.db_name),
    )
    .await
    {
        Ok(_) => {
            audit_einvoice(&state, &user, &db_ctx, Uuid::nil(), "code_sync_enqueued").await;
            flash_redirect(
                "/accounting/einvoice",
                FlashKind::Info,
                "LHDN code sync queued — catalogues refresh in the background.",
            )
        }
        Err(e) => {
            error!("code sync enqueue failed: {e}");
            flash_redirect(
                "/accounting/einvoice",
                FlashKind::Error,
                "Could not queue the code sync — check the server logs.",
            )
        }
    }
}

async fn audit_einvoice(
    state: &AppState,
    user: &AuthUser,
    db_ctx: &DatabaseContext,
    id: Uuid,
    action: &str,
) {
    let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("acc_einvoice", id.to_string())
        .with_details(json!({ "action": action }));
    if let Err(e) = state.audit.log(entry).await {
        error!("audit write failed: {e}");
    }
}
