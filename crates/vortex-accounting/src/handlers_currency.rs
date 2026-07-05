//! Currency administration — exchange rates and FX revaluation.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use crate::handlers::{page_shell, render_sidebar};

pub fn currency_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounting/currency-rates", get(rates_page))
        .route("/accounting/currency-rates", post(add_rate))
        .route("/accounting/currency-rates/sync-bnm", post(sync_bnm))
        .route("/accounting/revaluation", get(revaluation_page))
        .route("/accounting/revaluation", post(run_revaluation))
}

async fn rates_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT c.code, c.name, r.rate, r.rate_date \
         FROM currency_rates r JOIN currencies c ON c.id = r.currency_id \
         ORDER BY r.rate_date DESC, c.code LIMIT 100",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut trs = String::new();
    for r in &rows {
        let rate: Decimal = r.get("rate");
        let myr_per_unit = if rate.is_zero() {
            "—".to_string()
        } else {
            (Decimal::ONE / rate).round_dp(6).to_string()
        };
        trs.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td class=\"text-right font-mono\">{}</td>\
             <td class=\"text-right font-mono\">{}</td></tr>",
            r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("rate_date"),
            esc(&r.get::<String, _>("code")),
            rate.normalize(),
            myr_per_unit,
        ));
    }
    let currencies = vortex_plugin_sdk::sqlx::query(
        "SELECT code FROM currencies WHERE active AND code <> 'MYR' ORDER BY code",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let options: String = currencies
        .iter()
        .map(|r| {
            let c: String = r.get("code");
            format!("<option value=\"{0}\">{0}</option>", esc(&c))
        })
        .collect();
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Currency Rates</h1>
<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<form method="post" action="/accounting/currency-rates" class="flex gap-3 items-end flex-wrap">
<label class="form-control"><span class="label-text mb-1">Currency</span>
<select name="code" class="select select-bordered select-sm">{options}</select></label>
<label class="form-control"><span class="label-text mb-1">Units per 1 MYR</span>
<input name="rate" type="number" step="any" required class="input input-bordered input-sm" placeholder="0.2127"/></label>
<label class="form-control"><span class="label-text mb-1">Date</span>
<input name="rate_date" type="date" class="input input-bordered input-sm"/></label>
<button class="btn btn-primary btn-sm">Add Rate</button>
</form>
<form method="post" action="/accounting/currency-rates/sync-bnm" class="mt-2">
<button class="btn btn-sm btn-outline">Fetch BNM rates now</button>
<span class="text-xs opacity-60 ml-2">Bank Negara Malaysia KL interbank middle rates — also synced automatically twice daily for active currencies.</span>
</form>
<p class="text-xs opacity-60 mt-2">Enter the commerce convention: currency units per 1 MYR
(e.g. USD 0.2127 when 1 USD = RM 4.70). The MYR-per-unit column shows the accounting view.</p>
</div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<table class="table table-sm"><thead><tr><th>Date</th><th>Currency</th>
<th class="text-right">Units / MYR</th><th class="text-right">MYR / Unit</th></tr></thead>
<tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Currency Rates", &content)).into_response()
}

async fn add_rate(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().rev().find(|(pk, _)| pk == k).map(|(_, v)| v.trim());
    let code = get("code").unwrap_or_default();
    let rate: Option<Decimal> = get("rate").and_then(|s| s.parse().ok());
    let date: vortex_plugin_sdk::chrono::NaiveDate = get("rate_date")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| vortex_plugin_sdk::chrono::Utc::now().date_naive());
    let Some(rate) = rate.filter(|r| *r > Decimal::ZERO) else {
        return (StatusCode::BAD_REQUEST, "Rate must be a positive number").into_response();
    };
    let currency_id: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM currencies WHERE code = $1 AND active",
    )
    .bind(code)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(currency_id) = currency_id else {
        return (StatusCode::BAD_REQUEST, "Unknown currency").into_response();
    };
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO currency_rates (currency_id, rate, rate_date) VALUES ($1, $2, $3) \
         ON CONFLICT (currency_id, rate_date) DO UPDATE SET rate = EXCLUDED.rate",
    )
    .bind(currency_id)
    .bind(rate)
    .bind(date)
    .execute(&db)
    .await
    {
        error!("rate insert failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response();
    }
    audit_fx(&state, &user, &db_ctx, "rate_added", json!({"code": code, "rate": rate.to_string(), "date": date})).await;
    Redirect::to("/accounting/currency-rates").into_response()
}


/// Manual BNM pull — same code path as the twice-daily scheduler.
async fn sync_bnm(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    match crate::bnm::sync_rates(&db).await {
        Ok(n) if n > 0 => {
            audit_fx(&state, &user, &db_ctx, "bnm_synced", json!({"currencies": n})).await;
            flash_redirect(
                "/accounting/currency-rates",
                FlashKind::Success,
                &format!("BNM rates fetched — {n} currencies updated."),
            )
        }
        Ok(_) => flash_redirect(
            "/accounting/currency-rates",
            FlashKind::Info,
            "BNM reached, but no active currencies matched — activate currencies (e.g. USD, SGD) to receive rates.",
        ),
        Err(e) => flash_redirect(
            "/accounting/currency-rates",
            FlashKind::Error,
            &format!("BNM sync failed — {e}"),
        ),
    }
}

async fn revaluation_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let as_of: vortex_plugin_sdk::chrono::NaiveDate = q
        .get("as_of")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| vortex_plugin_sdk::chrono::Utc::now().date_naive());
    let items = crate::currency::open_fx_items(&db, as_of).await.unwrap_or_default();
    let mut trs = String::new();
    let mut net = Decimal::ZERO;
    for item in &items {
        let new_rate = crate::currency::myr_rate(&db, &item.currency_code, as_of)
            .await
            .unwrap_or(item.booked_rate);
        let delta = crate::currency::fx_delta(item.open_currency, item.open_myr_booked, new_rate);
        net += delta;
        trs.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td class=\"text-right font-mono\">{}</td>\
             <td class=\"text-right font-mono\">{}</td><td class=\"text-right font-mono\">{}</td>\
             <td class=\"text-right font-mono {}\">{}</td></tr>",
            esc(&item.number),
            esc(&item.currency_code),
            item.open_currency.round_dp(2),
            item.booked_rate.round_dp(4),
            new_rate.round_dp(4),
            if delta < Decimal::ZERO { "text-error" } else { "text-success" },
            delta,
        ));
    }
    if trs.is_empty() {
        trs = "<tr><td colspan=\"6\" class=\"text-center opacity-60 py-6\">No open foreign-currency items as of this date.</td></tr>".into();
    }
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">FX Revaluation</h1>
<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<form method="get" class="flex gap-3 items-end">
<label class="form-control"><span class="label-text mb-1">As of</span>
<input name="as_of" type="date" value="{as_of}" class="input input-bordered input-sm"/></label>
<button class="btn btn-sm btn-outline">Preview</button>
</form></div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<table class="table table-sm"><thead><tr><th>Document</th><th>Currency</th>
<th class="text-right">Open (CCY)</th><th class="text-right">Booked Rate</th>
<th class="text-right">Rate {as_of}</th><th class="text-right">Unrealized Δ (MYR)</th></tr></thead>
<tbody>{trs}</tbody>
<tfoot><tr class="font-bold"><td colspan="5" class="text-right">Net unrealized</td>
<td class="text-right font-mono">{net}</td></tr></tfoot></table>
<form method="post" action="/accounting/revaluation" class="mt-4">
<input type="hidden" name="as_of" value="{as_of}"/>
<button class="btn btn-primary btn-sm" {disabled}>Post revaluation (auto-reverses next day)</button>
</form></div></div>"##,
        as_of = as_of,
        trs = trs,
        net = net,
        disabled = if items.is_empty() { "disabled" } else { "" },
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "FX Revaluation", &content)).into_response()
}

async fn run_revaluation(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let as_of: vortex_plugin_sdk::chrono::NaiveDate = pairs
        .iter()
        .rev()
        .find(|(k, _)| k == "as_of")
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or_else(|| vortex_plugin_sdk::chrono::Utc::now().date_naive());
    match crate::currency::revalue_open_items(&db, &state.pool, user.id, None, as_of).await {
        Ok(Some((reval, reversal))) => {
            audit_fx(&state, &user, &db_ctx, "revaluation_posted",
                json!({"as_of": as_of, "move": reval, "reversal": reversal})).await;
            Redirect::to(&format!("/accounting/moves/{reval}")).into_response()
        }
        Ok(None) => Redirect::to("/accounting/revaluation").into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!(
                "<p>Revaluation failed: {}</p>",
                vortex_plugin_sdk::framework::html_escape(&e.to_string())
            )),
        )
            .into_response(),
    }
}

async fn audit_fx(
    state: &AppState,
    user: &AuthUser,
    db_ctx: &DatabaseContext,
    action: &str,
    details: vortex_plugin_sdk::serde_json::Value,
) {
    let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("acc_fx", action.to_string())
        .with_details(details);
    if let Err(e) = state.audit.log(entry).await {
        error!("audit write failed: {e}");
    }
}
