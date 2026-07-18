//! IWK → General Ledger: summarized posting + subledger reconciliation.
//!
//! `iwk_bill` is the receivables **subledger** (per-customer detail). This
//! module posts **period totals** to the GL — one balanced journal per
//! billing run — the way SAP FI-CA / Oracle CC&B feed the ledger, and
//! reconciles the control-account balance back to the subledger.

use rust_decimal::Decimal;
use uuid::Uuid;
use vortex_accounting::service::{self, MoveLine, NewMove};
use vortex_plugin_sdk::orm::ConnectionPool;
use vortex_plugin_sdk::sqlx::{PgPool, Row};

/// Dedicated GL accounts (migration 002). We resolve by code and fall back
/// to the company defaults so posting still works if the dedicated accounts
/// were never seeded (e.g. accounting installed later).
const ACC_RECEIVABLE: &str = "1220"; // Sewerage Receivables (control)
const REV_DOMESTIC: &str = "4200"; // Sewerage Revenue — Domestic
const REV_COMMERCIAL: &str = "4210"; // Sewerage Revenue — Commercial

/// Outcome of posting a run to the GL.
pub struct PostSummary {
    pub already_posted: bool,
    pub move_number: String,
    pub bill_count: i64,
    pub ar_total: Decimal,
    pub rev_domestic: Decimal,
    pub rev_commercial: Decimal,
}

/// Reconciliation snapshot: the subledger AR vs the GL control balance.
pub struct Recon {
    /// Σ outstanding on issued bills (the subledger).
    pub subledger_ar: Decimal,
    /// Balance of the Sewerage Receivables control account in the GL.
    pub gl_ar: Decimal,
    /// subledger − GL. Zero == reconciled.
    pub variance: Decimal,
    pub runs_total: i64,
    pub runs_posted: i64,
    /// Σ collections posted to the GL (Dr Bank).
    pub collected: Decimal,
    /// Σ unconsumed customer credit (advances liability).
    pub advances: Decimal,
    /// Payments captured but not yet posted to the GL.
    pub unposted_payments: i64,
}

/// Resolve an account by code, falling back to the company default for `role`
/// ("receivable" | "income") when the dedicated account is absent.
async fn account_or_default(
    db: &PgPool,
    company_id: Option<Uuid>,
    code: &str,
    role: &str,
) -> Result<Uuid, String> {
    if let Some(id) = service::account_by_code(db, company_id, code)
        .await
        .map_err(|e| e.to_string())?
    {
        return Ok(id);
    }
    service::default_account(db, company_id, role)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no account for code {code} or default role '{role}' — set up the chart of accounts"))
}

/// Post one billing run's totals to the GL as a single balanced journal.
/// Idempotent: a run already in `iwk_gl_batch` returns `already_posted`.
pub async fn post_run_to_gl(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    company_id: Option<Uuid>,
    run_id: Uuid,
) -> Result<PostSummary, String> {
    // Idempotency guard — has this run already been posted?
    if let Some(row) = vortex_plugin_sdk::sqlx::query(
        "SELECT move_number, bill_count, ar_total, rev_domestic, rev_commercial \
         FROM iwk_gl_batch WHERE run_id = $1",
    )
    .bind(run_id)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?
    {
        return Ok(PostSummary {
            already_posted: true,
            move_number: row.try_get::<Option<String>, _>("move_number").ok().flatten().unwrap_or_default(),
            bill_count: row.try_get("bill_count").unwrap_or(0),
            ar_total: row.try_get("ar_total").unwrap_or_default(),
            rev_domestic: row.try_get("rev_domestic").unwrap_or_default(),
            rev_commercial: row.try_get("rev_commercial").unwrap_or_default(),
        });
    }

    // Aggregate the subledger: revenue by category for this run's issued bills.
    let agg = vortex_plugin_sdk::sqlx::query(
        "SELECT COUNT(*)::bigint AS bill_count, \
                COALESCE(SUM(current_charge) FILTER (WHERE category = 'domestic'),   0) AS dom, \
                COALESCE(SUM(current_charge) FILTER (WHERE category = 'commercial'), 0) AS com \
         FROM iwk_bill WHERE run_id = $1 AND record_state = 'issued'",
    )
    .bind(run_id)
    .fetch_one(db)
    .await
    .map_err(|e| e.to_string())?;

    let bill_count: i64 = agg.try_get("bill_count").unwrap_or(0);
    let rev_domestic: Decimal = agg.try_get("dom").unwrap_or_default();
    let rev_commercial: Decimal = agg.try_get("com").unwrap_or_default();
    let ar_total = rev_domestic + rev_commercial;

    if ar_total.is_zero() {
        return Err("nothing to post: run has no issued bills with a charge".to_string());
    }

    // Resolve accounts.
    let ar_account = account_or_default(db, company_id, ACC_RECEIVABLE, "receivable").await?;
    let dom_account = account_or_default(db, company_id, REV_DOMESTIC, "income").await?;
    let com_account = account_or_default(db, company_id, REV_COMMERCIAL, "income").await?;

    // Build the balanced summary journal. No partner: this is an aggregate
    // control posting — per-customer detail lives in the iwk_bill subledger.
    let mut lines = vec![MoveLine::debit(ar_account, ar_total, Some("Sewerage receivables"))];
    if !rev_domestic.is_zero() {
        lines.push(MoveLine::credit(dom_account, rev_domestic, Some("Sewerage revenue — domestic")));
    }
    if !rev_commercial.is_zero() {
        lines.push(MoveLine::credit(com_account, rev_commercial, Some("Sewerage revenue — commercial")));
    }

    let today = chrono::Utc::now().date_naive();
    let origin = format!("iwk_billing_run:{run_id}");
    let new_move = NewMove {
        journal_code: "SAL",
        move_date: today,
        move_type: "entry",
        ref_: Some("IWK sewerage billing run"),
        narration: Some("Summarized sewerage billing — see IWK subledger for per-customer detail"),
        partner_id: None,
        origin_ref: Some(origin.as_str()),
        company_id,
        lines,
    };

    let (move_id, move_number) = service::create_and_post(db, seq_pool, user_id, &new_move)
        .await
        .map_err(|e| format!("posting failed: {e}"))?;

    // Record the posting (also our idempotency key).
    vortex_plugin_sdk::sqlx::query(
        "INSERT INTO iwk_gl_batch \
           (run_id, move_id, move_number, bill_count, ar_total, rev_domestic, rev_commercial, posted_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (run_id) DO NOTHING",
    )
    .bind(run_id)
    .bind(move_id)
    .bind(&move_number)
    .bind(bill_count)
    .bind(ar_total)
    .bind(rev_domestic)
    .bind(rev_commercial)
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(PostSummary {
        already_posted: false,
        move_number,
        bill_count,
        ar_total,
        rev_domestic,
        rev_commercial,
    })
}

/// Reconcile the sewerage subledger against the GL control account.
pub async fn reconciliation(db: &PgPool, company_id: Option<Uuid>) -> Result<Recon, String> {
    // Subledger: outstanding on issued bills.
    let subledger_ar: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COALESCE(SUM(total - payments), 0) FROM iwk_bill WHERE record_state = 'issued'",
    )
    .fetch_one(db)
    .await
    .map_err(|e| e.to_string())?;

    // GL: balance of the Sewerage Receivables control account (posted moves).
    let gl_ar: Decimal = match service::account_by_code(db, company_id, ACC_RECEIVABLE)
        .await
        .map_err(|e| e.to_string())?
    {
        Some(acc) => vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT COALESCE(SUM(l.debit - l.credit), 0) \
             FROM acc_move_line l JOIN acc_move m ON m.id = l.move_id \
             WHERE l.account_id = $1 AND m.state = 'posted'",
        )
        .bind(acc)
        .fetch_one(db)
        .await
        .map_err(|e| e.to_string())?,
        None => Decimal::ZERO,
    };

    let (runs_total, runs_posted) = {
        let row = vortex_plugin_sdk::sqlx::query(
            "SELECT (SELECT COUNT(*) FROM batch_run WHERE run_kind = 'iwk.billing_run')::bigint AS total, \
                    (SELECT COUNT(*) FROM iwk_gl_batch)::bigint AS posted",
        )
        .fetch_one(db)
        .await
        .map_err(|e| e.to_string())?;
        (row.try_get::<i64, _>("total").unwrap_or(0), row.try_get::<i64, _>("posted").unwrap_or(0))
    };

    // Collections posted + customer advances outstanding + unposted payments.
    let collected: Decimal =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT COALESCE(SUM(bank_total), 0) FROM iwk_gl_payment_batch")
            .fetch_one(db)
            .await
            .map_err(|e| e.to_string())?;
    let advances: Decimal =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT COALESCE(SUM(credit_balance), 0) FROM iwk_account")
            .fetch_one(db)
            .await
            .map_err(|e| e.to_string())?;
    let unposted_payments: i64 =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT COUNT(*) FROM iwk_payment WHERE NOT posted")
            .fetch_one(db)
            .await
            .map_err(|e| e.to_string())?;

    Ok(Recon {
        subledger_ar,
        gl_ar,
        variance: subledger_ar - gl_ar,
        runs_total,
        runs_posted,
        collected,
        advances,
        unposted_payments,
    })
}
