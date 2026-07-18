//! IWK payments: capture (manual + bulk), open-item FIFO allocation to bills,
//! and summarized GL posting — the collection mirror of [`crate::gl`].
//!
//! A payment settles the customer's oldest open bills first; any excess is
//! held as account credit. The GL sees one journal per collection batch
//! (Dr Bank / Cr Receivables / Cr Customer Advances), never one per payment.

use rust_decimal::Decimal;
use uuid::Uuid;
use vortex_accounting::service::{self, MoveLine, NewMove};
use vortex_plugin_sdk::orm::ConnectionPool;
use vortex_plugin_sdk::sqlx::{PgPool, Row};

const ACC_RECEIVABLE: &str = "1220"; // Sewerage Receivables (control)
const ACC_BANK: &str = "1100"; // Bank
const ACC_ADVANCE: &str = "2050"; // Customer Advances (credit held)

pub struct PaymentResult {
    pub payment_no: String,
    pub allocated: Decimal,
    pub credit: Decimal,
}

/// Register one payment against a contract: allocate it FIFO across the
/// account's open bills (oldest first), flipping each to `paid` when settled;
/// any remainder becomes account credit. Records the payment + its allocations
/// in the subledger (unposted — a later batch posts the total to the GL).
pub async fn register_payment(
    db: &PgPool,
    account_id: Uuid,
    amount: Decimal,
    payment_date: chrono::NaiveDate,
    method: &str,
    reference: &str,
    run_id: Option<Uuid>,
) -> Result<PaymentResult, String> {
    if amount <= Decimal::ZERO {
        return Err("payment amount must be positive".to_string());
    }
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;

    let contact_id: Uuid =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT contact_id FROM iwk_account WHERE id = $1")
            .bind(account_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "account not found".to_string())?;

    // Open bills, oldest first (FIFO). Lock so concurrent payments don't
    // double-allocate the same balance.
    let open_bills = vortex_plugin_sdk::sqlx::query(
        "SELECT id, (total - payments) AS open FROM iwk_bill \
         WHERE account_id = $1 AND record_state = 'issued' AND total > payments \
         ORDER BY period_start ASC FOR UPDATE",
    )
    .bind(account_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    // Insert the payment header first so allocations can FK to it.
    let payment_no: String = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO iwk_payment (payment_no, account_id, contact_id, amount, method, reference, payment_date, run_id) \
         VALUES ('PY' || lpad(nextval('iwk_payment_seq')::text, 10, '0'), $1, $2, $3, $4, $5, $6, $7) \
         RETURNING payment_no",
    )
    .bind(account_id)
    .bind(contact_id)
    .bind(amount)
    .bind(method)
    .bind(reference)
    .bind(payment_date)
    .bind(run_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("create payment: {e}"))?;

    let payment_id: Uuid =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM iwk_payment WHERE payment_no = $1")
            .bind(&payment_no)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

    let mut remaining = amount;
    for b in &open_bills {
        if remaining <= Decimal::ZERO {
            break;
        }
        let bill_id: Uuid = b.try_get("id").map_err(|e| e.to_string())?;
        let open: Decimal = b.try_get("open").unwrap_or_default();
        let alloc = remaining.min(open);
        if alloc <= Decimal::ZERO {
            continue;
        }

        vortex_plugin_sdk::sqlx::query(
            "UPDATE iwk_bill SET payments = payments + $2, \
                record_state = CASE WHEN payments + $2 >= total THEN 'paid' ELSE record_state END \
             WHERE id = $1",
        )
        .bind(bill_id)
        .bind(alloc)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO iwk_payment_alloc (payment_id, bill_id, amount) VALUES ($1, $2, $3)",
        )
        .bind(payment_id)
        .bind(bill_id)
        .bind(alloc)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        remaining -= alloc;
    }

    let credit = remaining; // unallocated excess → account credit
    let allocated = amount - credit;

    vortex_plugin_sdk::sqlx::query("UPDATE iwk_payment SET allocated = $2, credit = $3 WHERE id = $1")
        .bind(payment_id)
        .bind(allocated)
        .bind(credit)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    if credit > Decimal::ZERO {
        vortex_plugin_sdk::sqlx::query(
            "UPDATE iwk_account SET credit_balance = credit_balance + $2 WHERE id = $1",
        )
        .bind(account_id)
        .bind(credit)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }

    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(PaymentResult { payment_no, allocated, credit })
}

pub struct ImportSummary {
    pub run_id: Uuid,
    pub count: usize,
    pub errors: Vec<String>,
}

/// Bulk import a collection file: lines of `account_no,amount[,reference]`.
/// Each becomes a payment in one collection batch (`run_id`). Bad lines are
/// skipped and reported rather than aborting the batch.
pub async fn import_payments(
    db: &PgPool,
    body: &str,
    payment_date: chrono::NaiveDate,
    method: &str,
) -> Result<ImportSummary, String> {
    let run_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO batch_run (id, run_kind, status, chunk_size, total_items, processed_items, started_at, finished_at, params) \
         VALUES (gen_random_uuid(), 'iwk.collection_run', 'completed', 1000, 0, 0, NOW(), NOW(), \
                 jsonb_build_object('method', $1::text)) RETURNING id",
    )
    .bind(method)
    .fetch_one(db)
    .await
    .map_err(|e| e.to_string())?;

    let mut count = 0usize;
    let mut errors = Vec::new();
    for (i, raw) in body.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if cols.len() < 2 {
            errors.push(format!("line {}: expected account_no,amount[,ref]", i + 1));
            continue;
        }
        let account_no = cols[0];
        let amount = match cols[1].parse::<Decimal>() {
            Ok(a) => a,
            Err(_) => {
                errors.push(format!("line {}: bad amount '{}'", i + 1, cols[1]));
                continue;
            }
        };
        let reference = cols.get(2).copied().unwrap_or("");

        let account_id: Option<Uuid> =
            vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM iwk_account WHERE account_no = $1")
                .bind(account_no)
                .fetch_optional(db)
                .await
                .map_err(|e| e.to_string())?;
        let Some(account_id) = account_id else {
            errors.push(format!("line {}: unknown account '{account_no}'", i + 1));
            continue;
        };

        match register_payment(db, account_id, amount, payment_date, method, reference, Some(run_id)).await {
            Ok(_) => count += 1,
            Err(e) => errors.push(format!("line {} ({account_no}): {e}", i + 1)),
        }
    }

    vortex_plugin_sdk::sqlx::query("UPDATE batch_run SET total_items = $2, processed_items = $2 WHERE id = $1")
        .bind(run_id)
        .bind(count as i64)
        .execute(db)
        .await
        .map_err(|e| e.to_string())?;

    Ok(ImportSummary { run_id, count, errors })
}

pub struct PaymentPostSummary {
    pub already_posted: bool,
    pub move_number: String,
    pub payment_count: i64,
    pub bank_total: Decimal,
    pub ar_total: Decimal,
    pub advance_total: Decimal,
}

async fn account_or_default(
    db: &PgPool,
    company_id: Option<Uuid>,
    code: &str,
    role: &str,
) -> Result<Uuid, String> {
    if let Some(id) = service::account_by_code(db, company_id, code).await.map_err(|e| e.to_string())? {
        return Ok(id);
    }
    service::default_account(db, company_id, role)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no account for code {code} / role '{role}'"))
}

/// Post all unposted payments to the GL as one summarized collection journal:
/// Dr Bank / Cr Sewerage Receivables (allocated) / Cr Customer Advances
/// (overpayment). Marks the payments posted. Returns the batch totals.
pub async fn post_payments_to_gl(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    company_id: Option<Uuid>,
) -> Result<PaymentPostSummary, String> {
    let agg = vortex_plugin_sdk::sqlx::query(
        "SELECT COUNT(*)::bigint AS n, COALESCE(SUM(amount),0) AS bank, \
                COALESCE(SUM(allocated),0) AS ar, COALESCE(SUM(credit),0) AS adv \
         FROM iwk_payment WHERE NOT posted",
    )
    .fetch_one(db)
    .await
    .map_err(|e| e.to_string())?;

    let payment_count: i64 = agg.try_get("n").unwrap_or(0);
    let bank_total: Decimal = agg.try_get("bank").unwrap_or_default();
    let ar_total: Decimal = agg.try_get("ar").unwrap_or_default();
    let advance_total: Decimal = agg.try_get("adv").unwrap_or_default();

    if payment_count == 0 || bank_total.is_zero() {
        return Err("no unposted payments to post".to_string());
    }

    let bank = account_or_default(db, company_id, ACC_BANK, "receivable").await?;
    let ar = account_or_default(db, company_id, ACC_RECEIVABLE, "receivable").await?;
    let advance = account_or_default(db, company_id, ACC_ADVANCE, "payable").await?;

    let mut lines = vec![MoveLine::debit(bank, bank_total, Some("Sewerage collections"))];
    if !ar_total.is_zero() {
        lines.push(MoveLine::credit(ar, ar_total, Some("Settle sewerage receivables")));
    }
    if !advance_total.is_zero() {
        lines.push(MoveLine::credit(advance, advance_total, Some("Customer advances (overpayment)")));
    }

    let today = chrono::Utc::now().date_naive();
    let new_move = NewMove {
        journal_code: "BNK",
        move_date: today,
        move_type: "entry",
        ref_: Some("IWK sewerage collections"),
        narration: Some("Summarized sewerage collections — see IWK payment subledger for detail"),
        partner_id: None,
        origin_ref: Some("iwk_collection_batch"),
        company_id,
        lines,
    };

    let (move_id, move_number) = service::create_and_post(db, seq_pool, user_id, &new_move)
        .await
        .map_err(|e| format!("posting failed: {e}"))?;

    let batch_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO iwk_gl_payment_batch \
           (posting_date, payment_count, bank_total, ar_total, advance_total, move_id, move_number, posted_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(today)
    .bind(payment_count as i32)
    .bind(bank_total)
    .bind(ar_total)
    .bind(advance_total)
    .bind(move_id)
    .bind(&move_number)
    .bind(user_id)
    .fetch_one(db)
    .await
    .map_err(|e| e.to_string())?;

    vortex_plugin_sdk::sqlx::query("UPDATE iwk_payment SET posted = true, gl_batch_id = $1 WHERE NOT posted")
        .bind(batch_id)
        .execute(db)
        .await
        .map_err(|e| e.to_string())?;

    Ok(PaymentPostSummary {
        already_posted: false,
        move_number,
        payment_count,
        bank_total,
        ar_total,
        advance_total,
    })
}
