//! Durable e-invoice jobs: submission, validation polling, and LHDN
//! code-table sync. All ride the platform job queue — retries with
//! backoff, dead-letter on exhaustion, restart-safe.

use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::PgPool;
use vortex_plugin_sdk::tracing::{info, warn};
use vortex_plugin_sdk::uuid::Uuid;
use vortex_plugin_sdk::prelude::{JobContext, JobRegistry, NewJob};

use super::client::LhdnClient;
use super::flow;
use vortex_plugin_sdk::framework::AppState;

pub const KIND_SUBMIT: &str = "accounting.einvoice.submit";
pub const KIND_POLL: &str = "accounting.einvoice.poll";
pub const KIND_SYNC_CODES: &str = "accounting.lhdn.sync_codes";

/// Give up polling after this many attempts (~20 minutes at 30s).
const MAX_POLLS: i64 = 40;

/// Called from `Plugin::register_jobs`.
pub fn register(reg: &mut JobRegistry) {
    reg.register(KIND_SUBMIT, |ctx| async move { submit_job(ctx).await });
    reg.register(KIND_POLL, |ctx| async move { poll_job(ctx).await });
    reg.register(KIND_SYNC_CODES, |ctx| async move { sync_codes_job(ctx).await });
}

/// Post-posting hook: create the e-invoice row; in API mode with
/// auto-submit, enqueue the submit job. Called by the posting handler
/// (and by adopting modules after `documents::post_invoice`).
pub async fn after_post(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    move_id: Uuid,
) -> Result<(), String> {
    let Some(_) = flow::ensure_einvoice(db, move_id).await.map_err(|e| e.to_string())? else {
        return Ok(()); // not e-invoiceable (entry, vendor doc, or opted out)
    };
    let settings = flow::settings(db).await.map_err(|e| e.to_string())?;
    if settings.mode == "api" && settings.auto_submit {
        enqueue_submit(&state.db, db_name, move_id).await?;
    }
    Ok(())
}

pub async fn enqueue_submit(jobs_pool: &PgPool, db_name: &str, move_id: Uuid) -> Result<(), String> {
    vortex_plugin_sdk::framework::jobs::enqueue(
        jobs_pool,
        NewJob::new(KIND_SUBMIT, json!({ "move_id": move_id }))
            .for_db(db_name)
            .trace("acc_einvoice", &move_id.to_string())
            .max_attempts(5),
    )
    .await
    .map(|_| ())
}

fn client_from(settings: &flow::EinvoiceSettings) -> Result<LhdnClient, String> {
    let (Some(id), Some(secret)) = (settings.client_id.clone(), settings.client_secret.clone())
    else {
        return Err("MyInvois API credentials not configured".into());
    };
    LhdnClient::new(settings.production, id, secret)
}

async fn submit_job(ctx: JobContext) -> Result<(), String> {
    let move_id = ctx
        .payload
        .get("move_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("einvoice.submit: missing move_id")?;
    let db_name = ctx.db_name.clone().ok_or("einvoice.submit: no tenant")?;
    let db = ctx.pool().await;

    let settings = flow::settings(&db).await.map_err(|e| e.to_string())?;
    if settings.mode != "api" {
        info!("einvoice submit skipped: portal mode");
        return Ok(());
    }
    let api = client_from(&settings)?;
    if let Err(e) = flow::submit_via_api(&ctx.state, &db, &db_name, move_id, &api).await {
        // Surface the rejection on the invoice — a failure only
        // visible in the job queue reads as "nothing happened".
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE acc_einvoice SET error_json = $2 WHERE move_id = $1",
        )
        .bind(move_id)
        .bind(json!({ "message": e, "at": vortex_plugin_sdk::chrono::Utc::now() }))
        .execute(&db)
        .await;
        return Err(e);
    }
    // Submission accepted — clear any stale error from prior attempts.
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_einvoice SET error_json = NULL WHERE move_id = $1",
    )
    .bind(move_id)
    .execute(&db)
    .await;

    // Schedule the first poll shortly after submission.
    vortex_plugin_sdk::framework::jobs::enqueue(
        &ctx.state.db,
        NewJob::new(KIND_POLL, json!({ "move_id": move_id, "polls": 0 }))
            .for_db(&db_name)
            .trace("acc_einvoice", &move_id.to_string())
            .max_attempts(3)
            .run_at(vortex_plugin_sdk::chrono::Utc::now() + vortex_plugin_sdk::chrono::Duration::seconds(10)),
    )
    .await
    .map(|_| ())
}

async fn poll_job(ctx: JobContext) -> Result<(), String> {
    let move_id = ctx
        .payload
        .get("move_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("einvoice.poll: missing move_id")?;
    let polls = ctx.payload.get("polls").and_then(|v| v.as_i64()).unwrap_or(0);
    let db_name = ctx.db_name.clone().ok_or("einvoice.poll: no tenant")?;
    let db = ctx.pool().await;

    let settings = flow::settings(&db).await.map_err(|e| e.to_string())?;
    let api = client_from(&settings)?;
    let terminal = flow::poll_via_api(
        &ctx.state,
        &db,
        &db_name,
        move_id,
        &api,
        flow::portal_base(settings.production),
    )
    .await?;
    if terminal {
        return Ok(());
    }
    if polls >= MAX_POLLS {
        warn!("einvoice poll gave up after {MAX_POLLS} attempts for move {move_id}");
        vortex_plugin_sdk::sqlx::query(
            "UPDATE acc_einvoice SET error_json = $2 WHERE move_id = $1 AND status = 'submitted'",
        )
        .bind(move_id)
        .bind(json!({"warning": "validation still pending after poll limit — check the LHDN portal"}))
        .execute(&db)
        .await
        .map_err(|e| e.to_string())?;
        return Ok(());
    }
    // Not terminal: schedule the next poll.
    vortex_plugin_sdk::framework::jobs::enqueue(
        &ctx.state.db,
        NewJob::new(KIND_POLL, json!({ "move_id": move_id, "polls": polls + 1 }))
            .for_db(&db_name)
            .trace("acc_einvoice", &move_id.to_string())
            .max_attempts(3)
            .run_at(vortex_plugin_sdk::chrono::Utc::now() + vortex_plugin_sdk::chrono::Duration::seconds(30)),
    )
    .await
    .map(|_| ())
}

/// Sync the LHDN SDK code catalogues (classification, MSIC, UOM,
/// countries, states, tax types) into `acc_lhdn_code`. Air-gapped
/// installs keep the seeded critical sets and skip this job.
async fn sync_codes_job(ctx: JobContext) -> Result<(), String> {
    let db = ctx.pool().await;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let sets: [(&str, &str); 6] = [
        ("classification", "https://sdk.myinvois.hasil.gov.my/files/ClassificationCodes.json"),
        ("msic", "https://sdk.myinvois.hasil.gov.my/files/MSICSubCategoryCodes.json"),
        ("uom", "https://sdk.myinvois.hasil.gov.my/files/UnitTypes.json"),
        ("country", "https://sdk.myinvois.hasil.gov.my/files/CountryCodes.json"),
        ("state", "https://sdk.myinvois.hasil.gov.my/files/StateCodes.json"),
        ("tax_type", "https://sdk.myinvois.hasil.gov.my/files/TaxTypes.json"),
    ];
    let mut total = 0usize;
    for (code_type, url) in sets {
        let resp = match http.get(url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!("lhdn code sync: {url} → {}", r.status());
                continue;
            }
            Err(e) => {
                warn!("lhdn code sync: {url} failed: {e}");
                continue;
            }
        };
        let Ok(items) = resp.json::<vortex_plugin_sdk::serde_json::Value>().await else {
            continue;
        };
        let Some(arr) = items.as_array() else { continue };
        for item in arr {
            let code = ["Code", "code", "Id", "id"]
                .iter()
                .find_map(|k| item.get(*k))
                .map(|v| match v {
                    vortex_plugin_sdk::serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                });
            let desc = ["Description", "description", "Name", "name"]
                .iter()
                .find_map(|k| item.get(*k).and_then(|v| v.as_str()))
                .map(str::to_string);
            if let (Some(code), Some(desc)) = (code, desc) {
                let _ = vortex_plugin_sdk::sqlx::query(
                    "INSERT INTO acc_lhdn_code (code_type, code, description) \
                     VALUES ($1, $2, LEFT($3, 300)) \
                     ON CONFLICT (code_type, code) \
                     DO UPDATE SET description = LEFT($3, 300), active = TRUE",
                )
                .bind(code_type)
                .bind(&code)
                .bind(&desc)
                .execute(&db)
                .await;
                total += 1;
            }
        }
    }
    info!("lhdn code sync: upserted {total} codes");
    Ok(())
}
