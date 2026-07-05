//! Bank Negara Malaysia exchange-rate feed.
//!
//! BNM's Open API (no key required) publishes KL interbank rates as
//! MYR-per-`unit`-of-foreign-currency (some currencies quote per 100
//! units). The commerce convention is units-per-MYR, so:
//!
//!   commerce_rate = unit / middle_rate
//!
//! Only currencies that exist and are active in the tenant's
//! `currencies` table are updated — enable a currency to start
//! receiving its BNM rate.

use vortex_plugin_sdk::common::{VortexError, VortexResult};
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

const BNM_URL: &str = "https://api.bnm.gov.my/public/exchange-rate";
const BNM_ACCEPT: &str = "application/vnd.BNM.API.v1+json";

/// Fetch the latest BNM session rates and upsert `currency_rates`.
/// Returns the number of currencies updated.
pub async fn sync_rates(db: &PgPool) -> VortexResult<u32> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| VortexError::Internal(format!("http client: {e}")))?;
    let resp = http
        .get(BNM_URL)
        .header("Accept", BNM_ACCEPT)
        .send()
        .await
        .map_err(|e| VortexError::Internal(format!("BNM request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(VortexError::Internal(format!(
            "BNM API returned {}",
            resp.status()
        )));
    }
    let body: vortex_plugin_sdk::serde_json::Value = resp
        .json()
        .await
        .map_err(|e| VortexError::Internal(format!("BNM response parse: {e}")))?;
    let Some(items) = body.get("data").and_then(|d| d.as_array()) else {
        return Err(VortexError::Internal("BNM response missing data".into()));
    };

    // Active non-MYR currencies in this tenant, keyed by code.
    let wanted: std::collections::HashMap<String, Uuid> = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code FROM currencies WHERE active AND code <> 'MYR'",
    )
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?
    .iter()
    .map(|r| (r.get::<String, _>("code"), r.get::<Uuid, _>("id")))
    .collect();

    let mut updated = 0u32;
    for item in items {
        let Some(code) = item.get("currency_code").and_then(|c| c.as_str()) else {
            continue;
        };
        let Some(&currency_id) = wanted.get(code) else {
            continue;
        };
        let unit = item.get("unit").and_then(|u| u.as_i64()).unwrap_or(1);
        let Some(rate) = item.pointer("/rate/middle_rate").and_then(|r| r.as_f64()) else {
            continue;
        };
        let Some(date) = item
            .pointer("/rate/date")
            .and_then(|d| d.as_str())
            .and_then(|d| d.parse::<vortex_plugin_sdk::chrono::NaiveDate>().ok())
        else {
            continue;
        };
        if rate <= 0.0 || unit <= 0 {
            continue;
        }
        // MYR-per-unit → units-per-MYR (commerce convention).
        let Some(middle) = Decimal::from_f64_retain(rate) else { continue };
        let commerce_rate = (Decimal::from(unit) / middle).round_dp(8);
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO currency_rates (currency_id, rate, rate_date) VALUES ($1, $2, $3) \
             ON CONFLICT (currency_id, rate_date) DO UPDATE SET rate = EXCLUDED.rate",
        )
        .bind(currency_id)
        .bind(commerce_rate)
        .bind(date)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        updated += 1;
    }
    Ok(updated)
}

/// Scheduler entrypoint on the primary DB. BNM publishes twice on
/// business days; a half-day cadence keeps rates a session fresh.
pub async fn run_bnm_sync(state: &vortex_plugin_sdk::framework::AppState) -> VortexResult<()> {
    match sync_rates(&state.db).await {
        Ok(n) if n > 0 => {
            vortex_plugin_sdk::tracing::info!("BNM rate sync updated {n} currencies");
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) => {
            // Network flakiness must not mark the whole action failed
            // forever — log loudly, retry next run.
            vortex_plugin_sdk::tracing::warn!("BNM rate sync failed: {e}");
            Ok(())
        }
    }
}
