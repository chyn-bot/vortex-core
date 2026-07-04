//! Multi-currency engine (MFRS 121): transaction-date conversion,
//! realized FX on settlement, unrealized revaluation at period end.
//!
//! Conventions:
//! - Commerce `currency_rates.rate` = currency units per 1 MYR (base).
//!   Accounting stores `acc_move.currency_rate` = **MYR per unit**
//!   (`1/rate`), fixed at posting.
//! - GL lines on FX documents carry `amount_currency` (signed:
//!   positive debit) beside their MYR debit/credit.
//! - Settlement matches in **document currency**; the MYR difference
//!   between the legs posts automatically as realized FX gain/loss,
//!   linked via `acc_partial_reconcile.exchange_move_id`.
//! - Revaluation posts an unrealized entry as of the chosen date plus
//!   an automatic next-day reversal.

use vortex_plugin_sdk::chrono::NaiveDate;
use vortex_plugin_sdk::common::{VortexError, VortexResult};
use vortex_plugin_sdk::orm::commerce;
use vortex_plugin_sdk::orm::ConnectionPool;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use crate::service::{self, MoveLine, NewMove};

/// MYR per 1 unit of `code` on `date` (commerce stores units-per-MYR).
pub async fn myr_rate(db: &PgPool, code: &str, date: NaiveDate) -> VortexResult<Decimal> {
    if code == "MYR" {
        return Ok(Decimal::ONE);
    }
    let per_myr = commerce::get_rate(db, code, date).await?.ok_or_else(|| {
        VortexError::ValidationFailed(format!("no exchange rate for {code} on or before {date}"))
    })?;
    if per_myr.is_zero() {
        return Err(VortexError::ValidationFailed(format!("zero rate for {code}")));
    }
    Ok((Decimal::ONE / per_myr).round_dp(10))
}

/// MYR value of a document-currency amount at a fixed MYR-per-unit
/// rate. Pure — unit-tested.
pub fn to_myr(amount_currency: Decimal, myr_per_unit: Decimal) -> Decimal {
    (amount_currency * myr_per_unit).round_dp(2)
}

/// Realized/unrealized FX delta in MYR for an open document-currency
/// amount whose booked MYR value is `booked_myr`. Positive = gain for
/// an asset (receivable) side. Pure — unit-tested.
pub fn fx_delta(open_currency: Decimal, booked_myr: Decimal, new_myr_per_unit: Decimal) -> Decimal {
    (to_myr(open_currency, new_myr_per_unit) - booked_myr).round_dp(2)
}

/// FX gain/loss accounts from config.
pub async fn fx_accounts(
    db: &PgPool,
    realized: bool,
) -> VortexResult<(Uuid, Uuid)> {
    let (gain_col, loss_col) = if realized {
        ("realized_gain_account_id", "realized_loss_account_id")
    } else {
        ("unrealized_gain_account_id", "unrealized_loss_account_id")
    };
    let sql = format!(
        "SELECT {gain_col} AS gain, {loss_col} AS loss FROM acc_config \
         ORDER BY company_id NULLS LAST LIMIT 1"
    );
    let row = vortex_plugin_sdk::sqlx::query(&sql)
        .fetch_optional(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(r) = row else {
        return Err(VortexError::ValidationFailed("no acc_config row".into()));
    };
    let gain: Option<Uuid> = r.get("gain");
    let loss: Option<Uuid> = r.get("loss");
    match (gain, loss) {
        (Some(g), Some(l)) => Ok((g, l)),
        _ => Err(VortexError::ValidationFailed(
            "FX gain/loss accounts not configured in acc_config".into(),
        )),
    }
}

/// Post the realized-FX entry for a settlement leg and link it to the
/// partial reconcile. `delta_myr` positive means the MYR received
/// exceeds the MYR booked (gain on AR / loss on AP handled by caller
/// via sign). The entry re-balances the counterpart account so the
/// AR/AP nets to zero in MYR once fully settled in currency.
pub async fn post_realized_fx(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    company_id: Option<Uuid>,
    partner_id: Option<Uuid>,
    counterpart_account: Uuid,
    partial_reconcile_id: Uuid,
    delta_myr: Decimal,
    date: NaiveDate,
) -> VortexResult<Option<Uuid>> {
    if delta_myr.is_zero() {
        return Ok(None);
    }
    let (gain_acc, loss_acc) = fx_accounts(db, true).await?;
    let abs = delta_myr.abs();
    // delta > 0: counterpart (e.g. AR) needs an extra CREDIT of `abs`
    // to close in MYR, matched by a gain credit? No: think in terms of
    // closing the MYR residue on the counterpart account:
    //   AR booked 4700, settled 4600 in MYR, currency fully paid →
    //   residue 100 debit on AR must be credited away → loss 100 debit.
    // delta_myr = settled_myr - booked_myr = -100 → loss.
    let (lines, origin) = if delta_myr < Decimal::ZERO {
        (
            vec![
                MoveLine::debit(loss_acc, abs, Some("Realized FX loss")),
                {
                    let l = MoveLine::credit(counterpart_account, abs, Some("FX settlement difference"));
                    match partner_id { Some(p) => l.with_partner(p), None => l }
                },
            ],
            format!("acc_partial_reconcile:{partial_reconcile_id}"),
        )
    } else {
        (
            vec![
                {
                    let l = MoveLine::debit(counterpart_account, abs, Some("FX settlement difference"));
                    match partner_id { Some(p) => l.with_partner(p), None => l }
                },
                MoveLine::credit(gain_acc, abs, Some("Realized FX gain")),
            ],
            format!("acc_partial_reconcile:{partial_reconcile_id}"),
        )
    };
    let (move_id, _) = service::create_and_post(
        db,
        seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: date,
            move_type: "entry",
            ref_: Some("Realized FX difference"),
            narration: None,
            partner_id,
            origin_ref: Some(&origin),
            company_id,
            lines,
        },
    )
    .await?;
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_partial_reconcile SET exchange_move_id = $2 WHERE id = $1",
    )
    .bind(partial_reconcile_id)
    .bind(move_id)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(Some(move_id))
}

/// One open FX item for revaluation preview/posting.
#[derive(Debug, Clone)]
pub struct OpenFxItem {
    pub move_id: Uuid,
    pub number: String,
    pub currency_code: String,
    pub counterpart_account: Uuid,
    pub open_currency: Decimal,
    pub booked_rate: Decimal,
    pub open_myr_booked: Decimal,
    /// Signed from the company's perspective: positive = asset (AR).
    pub is_receivable: bool,
}

/// Open foreign-currency documents as of `as_of`.
pub async fn open_fx_items(db: &PgPool, as_of: NaiveDate) -> VortexResult<Vec<OpenFxItem>> {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT m.id, m.number, m.move_type, m.currency_rate, m.amount_residual_currency, \
                cur.code AS currency_code, l.account_id \
         FROM acc_move m \
         JOIN currencies cur ON cur.id = m.currency_id \
         JOIN acc_move_line l ON l.move_id = m.id \
         JOIN acc_account a ON a.id = l.account_id AND a.reconcile \
         WHERE m.state = 'posted' AND m.move_date <= $1 \
           AND m.currency_rate IS NOT NULL \
           AND COALESCE(m.amount_residual_currency, 0) <> 0 \
           AND cur.code <> 'MYR' \
         GROUP BY m.id, m.number, m.move_type, m.currency_rate, \
                  m.amount_residual_currency, cur.code, l.account_id",
    )
    .bind(as_of)
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(rows
        .iter()
        .map(|r| {
            let move_type: String = r.get("move_type");
            let rate: Decimal = r.get("currency_rate");
            let open: Decimal = r.get("amount_residual_currency");
            OpenFxItem {
                move_id: r.get("id"),
                number: r.get::<Option<String>, _>("number").unwrap_or_default(),
                currency_code: r.get("currency_code"),
                counterpart_account: r.get("account_id"),
                open_currency: open,
                booked_rate: rate,
                open_myr_booked: to_myr(open, rate),
                is_receivable: move_type.starts_with("customer"),
            }
        })
        .collect())
}

/// Post the unrealized-FX revaluation entry as of `as_of`, plus its
/// automatic next-day reversal. Returns (revaluation move, reversal).
pub async fn revalue_open_items(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    company_id: Option<Uuid>,
    as_of: NaiveDate,
) -> VortexResult<Option<(Uuid, Uuid)>> {
    let items = open_fx_items(db, as_of).await?;
    let (gain_acc, loss_acc) = fx_accounts(db, false).await?;
    let mut lines: Vec<MoveLine> = Vec::new();
    let mut net_gain = Decimal::ZERO;
    for item in &items {
        let new_rate = myr_rate(db, &item.currency_code, as_of).await?;
        // Direction: receivables carry positive open_currency; payables
        // negative (credit side) — fx_delta handles the sign.
        let delta = fx_delta(item.open_currency, item.open_myr_booked, new_rate);
        if delta.is_zero() {
            continue;
        }
        let label = format!("Revaluation {} {}", item.number, item.currency_code);
        if delta > Decimal::ZERO {
            lines.push(MoveLine::debit(item.counterpart_account, delta, Some(&label)));
            net_gain += delta;
        } else {
            lines.push(MoveLine::credit(item.counterpart_account, delta.abs(), Some(&label)));
            net_gain += delta;
        }
    }
    if lines.is_empty() {
        return Ok(None);
    }
    if net_gain > Decimal::ZERO {
        lines.push(MoveLine::credit(gain_acc, net_gain, Some("Unrealized FX gain")));
    } else if net_gain < Decimal::ZERO {
        lines.push(MoveLine::debit(loss_acc, net_gain.abs(), Some("Unrealized FX loss")));
    }
    // Mixed-direction batches can net exactly to zero only when every
    // per-line delta is zero — handled above.
    let (reval_id, _) = service::create_and_post(
        db,
        seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: as_of,
            move_type: "entry",
            ref_: Some("Unrealized FX revaluation"),
            narration: Some("Automatic period-end FX revaluation (reversed next day)"),
            partner_id: None,
            origin_ref: Some("acc_fx_revaluation"),
            company_id,
            lines,
        },
    )
    .await?;
    let next_day = as_of + vortex_plugin_sdk::chrono::Duration::days(1);
    let reversal_id = service::reverse_move(db, seq_pool, reval_id, next_day, user_id).await?;
    Ok(Some((reval_id, reversal_id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn myr_conversion_rounds_to_cents() {
        assert_eq!(to_myr(dec!(1000.00), dec!(4.7)), dec!(4700.00));
        assert_eq!(to_myr(dec!(333.33), dec!(4.6789)), dec!(1559.62));
    }

    #[test]
    fn fx_delta_signs() {
        // AR booked at 4.70, revalued at 4.60: 1000 USD open →
        // 4600 - 4700 = -100 (loss on the asset).
        assert_eq!(fx_delta(dec!(1000), dec!(4700.00), dec!(4.6)), dec!(-100.00));
        // Rate rises → gain.
        assert_eq!(fx_delta(dec!(1000), dec!(4700.00), dec!(4.8)), dec!(100.00));
        // Payables carry negative open amounts: rate rises → the debt
        // grows → delta negative (loss), symmetric by sign.
        assert_eq!(fx_delta(dec!(-1000), dec!(-4700.00), dec!(4.8)), dec!(-100.00));
    }

    #[test]
    fn zero_delta_when_rate_unchanged() {
        assert_eq!(fx_delta(dec!(500), dec!(2350.00), dec!(4.7)), dec!(0.00));
    }
}
