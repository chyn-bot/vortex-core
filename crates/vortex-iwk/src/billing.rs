//! IWK contract lifecycle: register a customer → open a contract account →
//! generate recurring bills from active contracts.
//!
//! Billing is an *output* of the contract, never hand-typed. The generator
//! is set-based (one pass over due contracts) and idempotent per period: the
//! `NOT EXISTS` guard means a cycle can't be billed twice, and `next_bill_date`
//! only advances for contracts that actually produced a bill.

use rust_decimal::Decimal;
use uuid::Uuid;
use vortex_plugin_sdk::sqlx::{PgPool, Row};

/// Well-known default company (every seeded contact uses it).
const DEFAULT_COMPANY: Uuid = Uuid::from_u128(0x1);

/// Months in a billing cycle. Unknown cycles fall back to semi-annual.
pub fn cycle_months(cycle: &str) -> i32 {
    match cycle {
        "monthly" => 1,
        "quarterly" => 3,
        _ => 6, // semi_annual
    }
}

pub struct RegisterResult {
    pub contact_id: Uuid,
    pub account_id: Uuid,
    pub account_no: String,
}

/// Register a new customer (creates the contact) and open their sewerage
/// contract (`iwk_account`). The first bill is due on the connection date.
#[allow(clippy::too_many_arguments)]
pub async fn register_customer(
    db: &PgPool,
    name: &str,
    street: &str,
    city: &str,
    phone: &str,
    category: &str,
    system_type: &str,
    units: i32,
    billing_cycle: &str,
    connection_date: chrono::NaiveDate,
    deposit: Decimal,
) -> Result<RegisterResult, String> {
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;

    let contact_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO contacts (company_id, name, contact_type, street, city, phone, active, record_state) \
         VALUES ($1, $2, 'customer', $3, $4, $5, true, 'draft') RETURNING id",
    )
    .bind(DEFAULT_COMPANY)
    .bind(name)
    .bind(street)
    .bind(city)
    .bind(phone)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("create contact: {e}"))?;

    let row = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO iwk_account \
           (account_no, contact_id, category, system_type, units, status, billing_cycle, \
            connection_date, next_bill_date, deposit, active) \
         VALUES ('PB' || lpad(nextval('iwk_account_seq')::text, 10, '0'), \
                 $1, $2, $3, $4, 'active', $5, $6, $6, $7, true) \
         RETURNING id, account_no",
    )
    .bind(contact_id)
    .bind(category)
    .bind(system_type)
    .bind(units)
    .bind(billing_cycle)
    .bind(connection_date)
    .bind(deposit)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("open account: {e}"))?;

    let account_id: Uuid = row.try_get("id").map_err(|e| e.to_string())?;
    let account_no: String = row.try_get("account_no").map_err(|e| e.to_string())?;

    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(RegisterResult { contact_id, account_id, account_no })
}

pub struct GenerateSummary {
    pub run_id: Uuid,
    pub bill_count: i64,
    pub total: Decimal,
}

/// How many active contracts are due to be billed on/before `period_end`.
pub async fn due_count(db: &PgPool, period_end: chrono::NaiveDate) -> Result<i64, String> {
    vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM iwk_account \
         WHERE status = 'active' AND next_bill_date IS NOT NULL AND next_bill_date <= $1",
    )
    .bind(period_end)
    .fetch_one(db)
    .await
    .map_err(|e| e.to_string())
}

/// Generate one bill for every active contract due on/before `period_end`,
/// as a tracked `batch_run` (so it flows into the GL posting page). Returns
/// how many bills were produced. Idempotent per contract-period.
pub async fn generate_bills_for_period(
    db: &PgPool,
    period_end: chrono::NaiveDate,
) -> Result<GenerateSummary, String> {
    let today = chrono::Utc::now().date_naive();
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;

    // Track the run.
    let run_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO batch_run (id, run_kind, status, chunk_size, total_items, processed_items, started_at, finished_at, params) \
         VALUES (gen_random_uuid(), 'iwk.billing_run', 'running', 1000, 0, 0, NOW(), NOW(), \
                 jsonb_build_object('period_end', $1::text, 'source', 'recurring')) RETURNING id",
    )
    .bind(period_end)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("create run: {e}"))?;

    // Generate bills for due contracts. period_start = the contract's
    // next_bill_date; months from its cycle; charge = tariff × months × units.
    // The NOT EXISTS guard makes a contract-period impossible to bill twice.
    vortex_plugin_sdk::sqlx::query(
        "INSERT INTO iwk_bill \
           (bill_no, account_id, contact_id, account_no, category, system_type, units, months, \
            period_start, period_end, bill_date, due_date, \
            prev_balance, payments, current_charge, adjustments, rounding, total, \
            jompay_biller, jompay_ref, run_id, record_state) \
         SELECT '60' || lpad(nextval('iwk_bill_seq')::text, 14, '0'), \
                a.id, a.contact_id, a.account_no, a.category, a.system_type, a.units, m.months, \
                a.next_bill_date, \
                (a.next_bill_date + make_interval(months => m.months) - INTERVAL '1 day')::date, \
                $2::date, ($2::date + INTERVAL '30 days')::date, \
                0, 0, t.monthly_rate * m.months * a.units, 0, 0, t.monthly_rate * m.months * a.units, \
                '68602', a.account_no, $1, 'issued' \
         FROM iwk_account a \
         JOIN iwk_tariff t ON t.category = a.category AND t.system_type = a.system_type AND t.active \
         CROSS JOIN LATERAL (SELECT CASE a.billing_cycle WHEN 'monthly' THEN 1 WHEN 'quarterly' THEN 3 ELSE 6 END AS months) m \
         WHERE a.status = 'active' AND a.next_bill_date IS NOT NULL AND a.next_bill_date <= $3 \
           AND NOT EXISTS (SELECT 1 FROM iwk_bill b WHERE b.account_id = a.id AND b.period_start = a.next_bill_date)",
    )
    .bind(run_id)
    .bind(today)
    .bind(period_end)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("generate bills: {e}"))?;

    // Advance the billing cursor for exactly the contracts that produced a
    // bill this run (a bill now exists for their current next_bill_date).
    vortex_plugin_sdk::sqlx::query(
        "UPDATE iwk_account a \
            SET next_bill_date = (a.next_bill_date \
                + make_interval(months => CASE a.billing_cycle WHEN 'monthly' THEN 1 WHEN 'quarterly' THEN 3 ELSE 6 END))::date \
          WHERE a.status = 'active' AND a.next_bill_date <= $1 \
            AND EXISTS (SELECT 1 FROM iwk_bill b WHERE b.account_id = a.id AND b.period_start = a.next_bill_date)",
    )
    .bind(period_end)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("advance cursor: {e}"))?;

    // Finalize the run counters.
    let agg = vortex_plugin_sdk::sqlx::query(
        "SELECT COUNT(*)::bigint AS n, COALESCE(SUM(total), 0) AS total FROM iwk_bill WHERE run_id = $1",
    )
    .bind(run_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let bill_count: i64 = agg.try_get("n").unwrap_or(0);
    let total: Decimal = agg.try_get("total").unwrap_or_default();

    vortex_plugin_sdk::sqlx::query(
        "UPDATE batch_run SET status = 'completed', total_items = $2, processed_items = $2, finished_at = NOW() WHERE id = $1",
    )
    .bind(run_id)
    .bind(bill_count)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(GenerateSummary { run_id, bill_count, total })
}
