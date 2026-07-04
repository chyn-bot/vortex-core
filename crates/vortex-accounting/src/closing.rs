//! Year-end close + MFRS statement engine.
//!
//! Closing: one entry zeroing every P&L account for the fiscal year
//! into Retained Earnings (3900), then the year is flagged closed and
//! the general lock advances. Reopen reverses the closing entry and
//! reopens the year.
//!
//! Statements: `section_balances` aggregates posted GL into the
//! account groups of migration 009; the four MFRS statements and the
//! indirect cash flow are rendered from it in `reports.rs`.

use vortex_plugin_sdk::chrono::NaiveDate;
use vortex_plugin_sdk::common::{VortexError, VortexResult};
use vortex_plugin_sdk::orm::ConnectionPool;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use crate::service::{self, MoveLine, NewMove};

/// One statement row: `(section, group_name, sequence, balance)`.
/// `balance` is signed debit-positive (assets/expenses positive).
pub type SectionBalance = (String, String, i32, Decimal);

/// Per-group signed balances. `from` = None gives cumulative (SOFP);
/// a period gives flows (SOPL, cash flow legs).
pub async fn section_balances(
    db: &PgPool,
    from: Option<NaiveDate>,
    to: NaiveDate,
) -> VortexResult<Vec<SectionBalance>> {
    let from_sql = from
        .map(|f| format!("AND m.move_date >= '{f}'"))
        .unwrap_or_default();
    let sql = format!(
        "SELECT g.section, g.name, g.sequence, \
                COALESCE(SUM(l.debit), 0) - COALESCE(SUM(l.credit), 0) AS balance \
         FROM acc_account_group g \
         JOIN acc_account a ON a.group_id = g.id \
         LEFT JOIN (acc_move_line l \
             JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted' \
                 AND m.move_date <= $1 {from_sql}) \
             ON l.account_id = a.id \
         GROUP BY g.id, g.section, g.name, g.sequence \
         ORDER BY g.sequence"
    );
    let rows = vortex_plugin_sdk::sqlx::query(&sql)
        .bind(to)
        .fetch_all(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(rows
        .iter()
        .map(|r| (r.get("section"), r.get("name"), r.get("sequence"), r.get("balance")))
        .collect())
}

/// Net profit (income − expenses) for a period, from the GL.
pub async fn period_profit(
    db: &PgPool,
    from: NaiveDate,
    to: NaiveDate,
) -> VortexResult<Decimal> {
    // Net profit = Σ(credit − debit) across every P&L account:
    // income accrues on the credit side, expenses reduce it.
    let profit: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COALESCE(SUM(l.credit - l.debit), 0) \
         FROM acc_move_line l \
         JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted' \
             AND m.move_date BETWEEN $1 AND $2 \
         JOIN acc_account a ON a.id = l.account_id \
         WHERE a.account_type IN ('income', 'income_other') OR a.account_type LIKE 'expense%'",
    )
    .bind(from)
    .bind(to)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(profit)
}

/// Close a fiscal year: refuse if drafts remain in the window, post a
/// closing entry zeroing every P&L account into Retained Earnings,
/// flag the year closed and advance the general lock date. Returns the
/// closing move (None when the year had no P&L activity).
pub async fn close_fiscal_year(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    fiscal_year_id: Uuid,
    advance_lock: bool,
) -> VortexResult<Option<Uuid>> {
    let fy = vortex_plugin_sdk::sqlx::query(
        "SELECT code, date_from, date_to, state FROM acc_fiscal_year WHERE id = $1",
    )
    .bind(fiscal_year_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(fy) = fy else {
        return Err(VortexError::ValidationFailed("fiscal year not found".into()));
    };
    if fy.get::<String, _>("state") != "open" {
        return Err(VortexError::ValidationFailed("fiscal year is not open".into()));
    }
    let code: String = fy.get("code");
    let date_from: NaiveDate = fy.get("date_from");
    let date_to: NaiveDate = fy.get("date_to");

    let drafts: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM acc_move \
         WHERE state = 'draft' AND move_date BETWEEN $1 AND $2",
    )
    .bind(date_from)
    .bind(date_to)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    if drafts > 0 {
        return Err(VortexError::ValidationFailed(format!(
            "{drafts} draft entrie(s) dated inside {code} — post or delete them first"
        )));
    }

    // Per-account P&L balances over the year.
    let pl_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT a.id, a.company_id, \
                COALESCE(SUM(l.debit), 0) - COALESCE(SUM(l.credit), 0) AS balance \
         FROM acc_account a \
         JOIN acc_move_line l ON l.account_id = a.id \
         JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted' \
             AND m.move_date BETWEEN $1 AND $2 \
         WHERE a.account_type IN ('income', 'income_other') \
            OR a.account_type LIKE 'expense%' \
         GROUP BY a.id, a.company_id \
         HAVING COALESCE(SUM(l.debit), 0) - COALESCE(SUM(l.credit), 0) <> 0",
    )
    .bind(date_from)
    .bind(date_to)
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let mut closing_move = None;
    if !pl_rows.is_empty() {
        let company_id: Option<Uuid> = pl_rows[0].get("company_id");
        let retained = service::account_by_code(db, company_id, "3900")
            .await?
            .ok_or_else(|| {
                VortexError::ValidationFailed("Retained Earnings 3900 missing".into())
            })?;
        let label = format!("Closing {code}");
        let mut lines = Vec::new();
        let mut net = Decimal::ZERO; // debit-positive residual
        for r in &pl_rows {
            let balance: Decimal = r.get("balance");
            let account: Uuid = r.get("id");
            // Zero the account: flip its year balance.
            if balance > Decimal::ZERO {
                lines.push(MoveLine::credit(account, balance, Some(&label)));
            } else {
                lines.push(MoveLine::debit(account, balance.abs(), Some(&label)));
            }
            net += balance;
        }
        // Counterpart into retained earnings. `net` is debit-positive:
        // a profitable year has net < 0 (P&L in aggregate carries a
        // credit balance), and zeroing it leaves the entry
        // debit-heavy — the profit is CREDITED to equity. A loss
        // mirrors as a debit. Break-even flips already balance.
        if net < Decimal::ZERO {
            lines.push(MoveLine::credit(retained, net.abs(), Some(&label)));
        } else if net > Decimal::ZERO {
            lines.push(MoveLine::debit(retained, net, Some(&label)));
        }
        let (move_id, _) = service::create_and_post(
            db,
            seq_pool,
            user_id,
            &NewMove {
                journal_code: "GEN",
                move_date: date_to,
                move_type: "entry",
                ref_: Some(&label),
                narration: Some("Year-end closing: P&L into retained earnings"),
                partner_id: None,
                origin_ref: Some("acc_fiscal_year"),
                company_id,
                lines,
            },
        )
        .await?;
        closing_move = Some(move_id);
    }

    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_fiscal_year SET state = 'closed', closing_move_id = $2 WHERE id = $1",
    )
    .bind(fiscal_year_id)
    .bind(closing_move)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    // Advance the general lock to the year end (never move it back).
    if advance_lock {
        vortex_plugin_sdk::sqlx::query(
            "UPDATE acc_config SET lock_date = GREATEST(COALESCE(lock_date, $1), $1)",
        )
        .bind(date_to)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }
    Ok(closing_move)
}

/// Reopen a closed year: reverse the closing entry (dated the first
/// day of the following year) and flip the state back. The lock date
/// is NOT rolled back automatically — that is a deliberate manual step.
pub async fn reopen_fiscal_year(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    fiscal_year_id: Uuid,
) -> VortexResult<()> {
    let fy = vortex_plugin_sdk::sqlx::query(
        "SELECT state, date_to, closing_move_id FROM acc_fiscal_year WHERE id = $1",
    )
    .bind(fiscal_year_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(fy) = fy else {
        return Err(VortexError::ValidationFailed("fiscal year not found".into()));
    };
    if fy.get::<String, _>("state") != "closed" {
        return Err(VortexError::ValidationFailed("fiscal year is not closed".into()));
    }
    // Reopening requires the general lock to be pulled back first —
    // otherwise the reversal itself could not post inside the year and
    // the books would stay silently locked.
    if let Some(closing) = fy.get::<Option<Uuid>, _>("closing_move_id") {
        let date_to: NaiveDate = fy.get("date_to");
        let reversal_date = date_to + vortex_plugin_sdk::chrono::Duration::days(1);
        service::reverse_move(db, seq_pool, closing, reversal_date, user_id).await?;
    }
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_fiscal_year SET state = 'open', closing_move_id = NULL WHERE id = $1",
    )
    .bind(fiscal_year_id)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // The closing logic is exercised end-to-end in tests/lifecycle.rs
    // (it needs a live GL). The pure helpers used by the statements
    // are covered in reports.rs / assets.rs.
}
