//! Recurring journal entries — a JSONB line template generated on a
//! monthly cadence by the daily scheduled action (rent, standing
//! charges, amortizations).

use vortex_plugin_sdk::chrono::{Datelike, NaiveDate};
use vortex_plugin_sdk::common::{VortexError, VortexResult};
use vortex_plugin_sdk::orm::ConnectionPool;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use crate::service::{self, MoveLine, NewMove};

/// `date` advanced by `months`, clamped to the target month's length
/// (Jan 31 + 1 month = Feb 28/29). Pure — unit-tested.
pub fn advance_months(date: NaiveDate, months: u32) -> NaiveDate {
    let zero_based = date.month0() + months;
    let year = date.year() + (zero_based / 12) as i32;
    let month = zero_based % 12 + 1;
    let last = crate::assets::month_end(NaiveDate::from_ymd_opt(year, month, 1).unwrap()).day();
    NaiveDate::from_ymd_opt(year, month, date.day().min(last)).unwrap()
}

/// One template line, parsed and validated from the JSONB array.
struct TemplateLine {
    account_id: Uuid,
    name: Option<String>,
    debit: Decimal,
    credit: Decimal,
    partner_id: Option<Uuid>,
    project_id: Option<Uuid>,
    department_id: Option<Uuid>,
}

async fn parse_template(
    db: &PgPool,
    company_id: Option<Uuid>,
    raw: &vortex_plugin_sdk::serde_json::Value,
) -> VortexResult<Vec<TemplateLine>> {
    let arr = raw
        .as_array()
        .ok_or_else(|| VortexError::ValidationFailed("template must be a JSON array".into()))?;
    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let field = |k: &str| item.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let dec = |k: &str| -> Decimal {
            item.get(k)
                .map(|v| {
                    v.as_str()
                        .map(|s| s.parse().unwrap_or_default())
                        .unwrap_or_else(|| {
                            v.as_f64()
                                .and_then(Decimal::from_f64_retain)
                                .unwrap_or_default()
                        })
                })
                .unwrap_or_default()
                .round_dp(2)
        };
        let code = field("account_code").ok_or_else(|| {
            VortexError::ValidationFailed(format!("template line {}: account_code missing", i + 1))
        })?;
        let account_id = service::account_by_code(db, company_id, &code)
            .await?
            .ok_or_else(|| {
                VortexError::ValidationFailed(format!("template line {}: unknown account {code}", i + 1))
            })?;
        let uuid = |k: &str| field(k).and_then(|s| s.parse().ok());
        out.push(TemplateLine {
            account_id,
            name: field("name"),
            debit: dec("debit"),
            credit: dec("credit"),
            partner_id: uuid("partner_id"),
            project_id: uuid("project_id"),
            department_id: uuid("department_id"),
        });
    }
    Ok(out)
}

/// Generate one occurrence of a recurring template dated `date`, then
/// advance `next_date`. Draft unless `auto_post`. Returns the move id.
pub async fn generate_occurrence(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    recurring_id: Uuid,
    date: NaiveDate,
) -> VortexResult<Uuid> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT name, journal_code, interval_months, next_date, end_date, auto_post, \
                ref, lines, company_id \
         FROM acc_recurring WHERE id = $1 AND active",
    )
    .bind(recurring_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(r) = row else {
        return Err(VortexError::ValidationFailed("recurring entry not found or inactive".into()));
    };
    let company_id: Option<Uuid> = r.get("company_id");
    let template: vortex_plugin_sdk::serde_json::Value = r.get("lines");
    let parsed = parse_template(db, company_id, &template).await?;
    if parsed.len() < 2 {
        return Err(VortexError::ValidationFailed("template needs at least two lines".into()));
    }
    let name: String = r.get("name");
    let journal_code: String = r.get("journal_code");
    let ref_: Option<String> = r.get("ref");
    let label = format!("{name} {date}");
    let lines: Vec<MoveLine> = parsed
        .iter()
        .map(|t| MoveLine {
            account_id: t.account_id,
            partner_id: t.partner_id,
            name: Some(t.name.clone().unwrap_or_else(|| label.clone())),
            debit: t.debit,
            credit: t.credit,
            currency_id: None,
            amount_currency: None,
            project_id: t.project_id,
            department_id: t.department_id,
        })
        .collect();
    let new_move = NewMove {
        journal_code: &journal_code,
        move_date: date,
        move_type: "entry",
        ref_: ref_.as_deref().or(Some(&label)),
        narration: None,
        partner_id: None,
        origin_ref: Some("acc_recurring"),
        company_id,
        lines,
    };
    let auto_post: bool = r.get("auto_post");
    let move_id = if auto_post {
        service::create_and_post(db, seq_pool, user_id, &new_move).await?.0
    } else {
        service::create_move(db, user_id, &new_move).await?
    };
    let interval: i32 = r.get("interval_months");
    let next = advance_months(r.get("next_date"), interval as u32);
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_recurring SET next_date = $2, last_move_id = $3, \
                active = active AND (end_date IS NULL OR $2 <= end_date) \
         WHERE id = $1",
    )
    .bind(recurring_id)
    .bind(next)
    .bind(move_id)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(move_id)
}

/// Generate every due occurrence (daily scheduled action body).
pub async fn generate_due(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    as_of: NaiveDate,
) -> VortexResult<u32> {
    let mut generated = 0u32;
    // Loop: a template overdue by several periods catches up one
    // occurrence per iteration.
    loop {
        let due: Vec<(Uuid, NaiveDate)> = vortex_plugin_sdk::sqlx::query_as(
            "SELECT id, next_date FROM acc_recurring \
             WHERE active AND next_date <= $1 \
               AND (end_date IS NULL OR next_date <= end_date)",
        )
        .bind(as_of)
        .fetch_all(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        if due.is_empty() {
            return Ok(generated);
        }
        for (id, next_date) in due {
            generate_occurrence(db, seq_pool, user_id, id, next_date).await?;
            generated += 1;
        }
        if generated > 1000 {
            return Err(VortexError::Internal("recurring generation runaway".into()));
        }
    }
}

/// Scheduler entrypoint on the primary DB.
pub async fn run_recurring(state: &vortex_plugin_sdk::framework::AppState) -> VortexResult<()> {
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
    let n = generate_due(&state.db, &state.pool, user, today).await?;
    if n > 0 {
        vortex_plugin_sdk::tracing::info!("recurring run generated {n} entrie(s)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        s.parse().unwrap()
    }

    #[test]
    fn advance_months_clamps_month_end() {
        assert_eq!(advance_months(d("2026-01-31"), 1), d("2026-02-28"));
        assert_eq!(advance_months(d("2028-01-31"), 1), d("2028-02-29"));
        assert_eq!(advance_months(d("2026-03-15"), 1), d("2026-04-15"));
        assert_eq!(advance_months(d("2026-11-30"), 3), d("2027-02-28"));
        assert_eq!(advance_months(d("2026-06-30"), 12), d("2027-06-30"));
    }
}
