//! Email a document to its partner — PDF rendered server-side
//! (headless Chromium), attached, and sent through the tenant SMTP
//! service. Runs on the durable job queue: restarts and SMTP hiccups
//! retry instead of losing the send.

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::tracing::info;
use vortex_plugin_sdk::uuid::Uuid;

pub const KIND_EMAIL: &str = "accounting.document.email";

pub fn register(reg: &mut JobRegistry) {
    reg.register(KIND_EMAIL, |ctx| async move { email_job(ctx).await });
}

async fn email_job(ctx: JobContext) -> Result<(), String> {
    let move_id = ctx
        .payload
        .get("move_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("document.email: missing move_id")?;
    let db_name = ctx.db_name.clone().ok_or("document.email: no tenant")?;
    let db = ctx.pool().await;

    let rendered = crate::handlers_documents::render_print_html(&ctx.state, &db, &db_name, move_id)
        .await?
        .ok_or("document.email: document not found")?;
    let Some(to) = rendered.partner_email.clone() else {
        return Err(format!(
            "no email address on {} — add one to the contact",
            rendered.partner_name
        ));
    };
    if !vortex_plugin_sdk::framework::pdf::available() {
        return Err("PDF engine not enabled in this build (rebuild with --features pdf)".into());
    }
    let opts = vortex_plugin_sdk::framework::pdf::PdfOptions::default();
    let pdf = vortex_plugin_sdk::framework::pdf::html_to_pdf(&rendered.html, &opts)
        .await
        .map_err(|e| format!("pdf render: {e}"))?;
    let fname = format!("{}.pdf", rendered.number.replace('/', "-"));
    let msg = vortex_plugin_sdk::framework::mail::EmailMessage::text(
        &to,
        format!("{} — total MYR {}", rendered.number, rendered.total),
        format!(
            "Dear {},\n\nPlease find attached {} for MYR {}.\n\nThank you.",
            rendered.partner_name, rendered.number, rendered.total
        ),
    )
    .with_attachment(fname, "application/pdf", pdf);
    vortex_plugin_sdk::framework::mail::send_default(&db, &msg, KIND_EMAIL)
        .await
        .map_err(|e| format!("send: {e}"))?;
    info!(number = %rendered.number, to = %to, "document emailed");
    let _ = json!({});
    Ok(())
}
