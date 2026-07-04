//! Fixed assets (MFRS 116) — straight-line depreciation schedule,
//! monthly posting run, disposal with gain/loss.
//!
//! Convention: full-month. The first depreciation posts at the end of
//! the month of `start_date`; the final period absorbs rounding so the
//! schedule sums exactly to `cost - salvage`.

use vortex_plugin_sdk::chrono::{Datelike, NaiveDate};
use vortex_plugin_sdk::common::{VortexError, VortexResult};
use vortex_plugin_sdk::orm::ConnectionPool;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use crate::service::{self, MoveLine, NewMove};

/// Last day of `date`'s month.
pub fn month_end(date: NaiveDate) -> NaiveDate {
    let (y, m) = (date.year(), date.month());
    let first_next = if m == 12 {
        NaiveDate::from_ymd_opt(y + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(y, m + 1, 1)
    };
    first_next.unwrap() - vortex_plugin_sdk::chrono::Duration::days(1)
}

/// Straight-line schedule: `(seq, dep_date, amount, cumulative)` per
/// month. Pure — unit-tested. Final period trues up rounding.
pub fn build_schedule(
    cost: Decimal,
    salvage: Decimal,
    life_months: u32,
    start_date: NaiveDate,
) -> Vec<(i32, NaiveDate, Decimal, Decimal)> {
    let depreciable = cost - salvage;
    if depreciable <= Decimal::ZERO || life_months == 0 {
        return Vec::new();
    }
    let monthly = (depreciable / Decimal::from(life_months)).round_dp(2);
    let mut out = Vec::with_capacity(life_months as usize);
    let mut cumulative = Decimal::ZERO;
    let mut date = month_end(start_date);
    for seq in 1..=life_months {
        let amount = if seq == life_months {
            (depreciable - cumulative).round_dp(2) // true-up
        } else {
            monthly
        };
        cumulative += amount;
        out.push((seq as i32, date, amount, cumulative));
        let next_month_first = date + vortex_plugin_sdk::chrono::Duration::days(1);
        date = month_end(next_month_first);
    }
    out
}

/// Confirm a draft asset: materialize its schedule and set it running.
pub async fn confirm_asset(db: &PgPool, asset_id: Uuid) -> VortexResult<usize> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT cost, salvage_value, life_months, start_date, state FROM acc_asset WHERE id = $1",
    )
    .bind(asset_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(r) = row else {
        return Err(VortexError::ValidationFailed("asset not found".into()));
    };
    if r.get::<String, _>("state") != "draft" {
        return Err(VortexError::ValidationFailed("only draft assets can be confirmed".into()));
    }
    let schedule = build_schedule(
        r.get("cost"),
        r.get("salvage_value"),
        r.get::<i32, _>("life_months") as u32,
        r.get("start_date"),
    );
    if schedule.is_empty() {
        return Err(VortexError::ValidationFailed(
            "nothing to depreciate (cost equals salvage value)".into(),
        ));
    }
    for (seq, dep_date, amount, cumulative) in &schedule {
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO acc_asset_depreciation (asset_id, seq, dep_date, amount, cumulative) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (asset_id, seq) DO NOTHING",
        )
        .bind(asset_id)
        .bind(seq)
        .bind(dep_date)
        .bind(amount)
        .bind(cumulative)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }
    vortex_plugin_sdk::sqlx::query("UPDATE acc_asset SET state = 'running' WHERE id = $1")
        .bind(asset_id)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(schedule.len())
}

/// Post every planned depreciation due on or before `as_of`.
/// Returns the number of periods posted.
pub async fn post_due_depreciation(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    as_of: NaiveDate,
) -> VortexResult<u32> {
    let due = vortex_plugin_sdk::sqlx::query(
        "SELECT d.id, d.asset_id, d.seq, d.dep_date, d.amount, d.cumulative, \
                a.name, a.depreciation_account_id, a.expense_account_id, \
                a.project_id, a.department_id, a.company_id, a.cost, a.salvage_value \
         FROM acc_asset_depreciation d \
         JOIN acc_asset a ON a.id = d.asset_id AND a.state = 'running' \
         WHERE d.state = 'planned' AND d.dep_date <= $1 \
         ORDER BY d.asset_id, d.seq",
    )
    .bind(as_of)
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let mut posted = 0u32;
    for d in &due {
        let dep_id: Uuid = d.get("id");
        let asset_id: Uuid = d.get("asset_id");
        let amount: Decimal = d.get("amount");
        let name: String = d.get("name");
        let seq: i32 = d.get("seq");
        let label = format!("Depreciation {name} #{seq}");
        let project: Option<Uuid> = d.get("project_id");
        let department: Option<Uuid> = d.get("department_id");
        let lines = vec![
            MoveLine::debit(d.get("expense_account_id"), amount, Some(&label))
                .with_dimensions(project, department),
            MoveLine::credit(d.get("depreciation_account_id"), amount, Some(&label)),
        ];
        // One un-postable period (e.g. behind a lock date) must not
        // block the rest of the batch — skip it and let the next run
        // retry.
        let move_id = match service::create_and_post(
            db,
            seq_pool,
            user_id,
            &NewMove {
                journal_code: "GEN",
                move_date: d.get("dep_date"),
                move_type: "entry",
                ref_: Some(&label),
                narration: None,
                partner_id: None,
                origin_ref: Some("acc_asset"),
                company_id: d.get("company_id"),
                lines,
            },
        )
        .await
        {
            Ok((id, _)) => id,
            Err(e) => {
                vortex_plugin_sdk::tracing::warn!("depreciation skipped for {label}: {e}");
                continue;
            }
        };
        vortex_plugin_sdk::sqlx::query(
            "UPDATE acc_asset_depreciation SET state = 'posted', move_id = $2 WHERE id = $1",
        )
        .bind(dep_id)
        .bind(move_id)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        posted += 1;
        // Fully depreciated once cumulative reaches cost - salvage.
        let cumulative: Decimal = d.get("cumulative");
        let depreciable = d.get::<Decimal, _>("cost") - d.get::<Decimal, _>("salvage_value");
        if cumulative >= depreciable {
            vortex_plugin_sdk::sqlx::query(
                "UPDATE acc_asset SET state = 'fully_depreciated' WHERE id = $1 AND state = 'running'",
            )
            .bind(asset_id)
            .execute(db)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        }
    }
    Ok(posted)
}

/// Dispose an asset: derecognize cost + accumulated depreciation,
/// book proceeds against the bank, and the balancing gain/loss.
/// Remaining planned periods are dropped. Returns the disposal move.
pub async fn dispose_asset(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    asset_id: Uuid,
    proceeds: Decimal,
    date: NaiveDate,
) -> VortexResult<Uuid> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT a.name, a.cost, a.state, a.asset_account_id, a.depreciation_account_id, \
                a.company_id, \
                COALESCE((SELECT SUM(d.amount) FROM acc_asset_depreciation d \
                          WHERE d.asset_id = a.id AND d.state = 'posted'), 0) AS accumulated \
         FROM acc_asset a WHERE a.id = $1",
    )
    .bind(asset_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(r) = row else {
        return Err(VortexError::ValidationFailed("asset not found".into()));
    };
    let state: String = r.get("state");
    if state != "running" && state != "fully_depreciated" {
        return Err(VortexError::ValidationFailed(format!(
            "cannot dispose an asset in state {state}"
        )));
    }
    if proceeds < Decimal::ZERO {
        return Err(VortexError::ValidationFailed("proceeds cannot be negative".into()));
    }
    let name: String = r.get("name");
    let cost: Decimal = r.get("cost");
    let accumulated: Decimal = r.get("accumulated");
    let company_id: Option<Uuid> = r.get("company_id");
    let nbv = cost - accumulated;
    let result = proceeds - nbv; // positive = gain
    let bank = service::account_by_type(db, company_id, "asset_bank")
        .await?
        .ok_or_else(|| VortexError::ValidationFailed("no bank account".into()))?;
    let gain = service::account_by_code(db, company_id, "4970")
        .await?
        .ok_or_else(|| VortexError::ValidationFailed("gain account 4970 missing".into()))?;
    let loss = service::account_by_code(db, company_id, "6970")
        .await?
        .ok_or_else(|| VortexError::ValidationFailed("loss account 6970 missing".into()))?;
    let label = format!("Disposal {name}");
    // Dr accumulated depreciation, Dr bank (proceeds), Cr asset cost,
    // and gain (Cr) / loss (Dr) balances.
    let mut lines = Vec::new();
    if accumulated > Decimal::ZERO {
        lines.push(MoveLine::debit(r.get("depreciation_account_id"), accumulated, Some(&label)));
    }
    if proceeds > Decimal::ZERO {
        lines.push(MoveLine::debit(bank, proceeds, Some(&label)));
    }
    lines.push(MoveLine::credit(r.get("asset_account_id"), cost, Some(&label)));
    if result > Decimal::ZERO {
        lines.push(MoveLine::credit(gain, result, Some(&label)));
    } else if result < Decimal::ZERO {
        lines.push(MoveLine::debit(loss, result.abs(), Some(&label)));
    }
    let (move_id, _) = service::create_and_post(
        db,
        seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: date,
            move_type: "entry",
            ref_: Some(&label),
            narration: None,
            partner_id: None,
            origin_ref: Some("acc_asset"),
            company_id,
            lines,
        },
    )
    .await?;
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_asset SET state = 'disposed', disposal_move_id = $2 WHERE id = $1",
    )
    .bind(asset_id)
    .bind(move_id)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    vortex_plugin_sdk::sqlx::query(
        "DELETE FROM acc_asset_depreciation WHERE asset_id = $1 AND state = 'planned'",
    )
    .bind(asset_id)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(move_id)
}

/// Scheduler entrypoint: post due depreciation on the primary DB.
pub async fn run_depreciation(state: &vortex_plugin_sdk::framework::AppState) -> VortexResult<()> {
    let user: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM users WHERE active ORDER BY created_at LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(user) = user else {
        return Ok(());
    };
    let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
    let posted = post_due_depreciation(&state.db, &state.pool, user, today).await?;
    if posted > 0 {
        vortex_plugin_sdk::tracing::info!("depreciation run posted {posted} period(s)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn d(s: &str) -> NaiveDate {
        s.parse().unwrap()
    }

    #[test]
    fn month_end_handles_year_boundary_and_leap() {
        assert_eq!(month_end(d("2026-01-15")), d("2026-01-31"));
        assert_eq!(month_end(d("2026-12-01")), d("2026-12-31"));
        assert_eq!(month_end(d("2028-02-05")), d("2028-02-29"));
    }

    #[test]
    fn schedule_trues_up_final_period() {
        // 10,000 over 36 months = 277.78/mo; final period absorbs the
        // 0.08 rounding difference.
        let s = build_schedule(dec!(10000), dec!(0), 36, d("2026-01-10"));
        assert_eq!(s.len(), 36);
        assert_eq!(s[0].1, d("2026-01-31"));
        assert_eq!(s[0].2, dec!(277.78));
        assert_eq!(s[35].2, dec!(277.70));
        assert_eq!(s[35].3, dec!(10000.00), "cumulative == depreciable");
        assert_eq!(s[35].1, d("2028-12-31"));
    }

    #[test]
    fn schedule_respects_salvage_and_rejects_degenerates() {
        let s = build_schedule(dec!(5000), dec!(500), 12, d("2026-06-01"));
        assert_eq!(s.last().unwrap().3, dec!(4500.00));
        assert!(build_schedule(dec!(1000), dec!(1000), 12, d("2026-01-01")).is_empty());
        assert!(build_schedule(dec!(1000), dec!(0), 0, d("2026-01-01")).is_empty());
    }
}
