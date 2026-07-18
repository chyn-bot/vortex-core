//! Customer-centric views: the IWK card on a contact's record page, and the
//! data for the full customer ledger (all accounts + all transactions with a
//! running balance).

use rust_decimal::Decimal;
use uuid::Uuid;
use vortex_plugin_sdk::sqlx::{PgPool, Row};

/// The IWK panel shown on a contact's record page (via `Plugin::record_panels`).
/// Lists the customer's sewerage account(s), a billed/paid/outstanding summary,
/// and a link to the full ledger. Returns "" for non-IWK contacts so the card
/// simply doesn't appear.
pub async fn contact_panel(db: &PgPool, contact_id: Uuid) -> Result<String, String> {
    let esc = vortex_plugin_sdk::framework::html_escape;

    let accounts = vortex_plugin_sdk::sqlx::query(
        "SELECT id, account_no, category, system_type, status, \
                to_char(next_bill_date,'DD/MM/YYYY') AS nb, \
                to_char(credit_balance,'FM999,990.00') AS credit \
         FROM iwk_account WHERE contact_id = $1 ORDER BY account_no",
    )
    .bind(contact_id)
    .fetch_all(db)
    .await
    .map_err(|e| e.to_string())?;

    if accounts.is_empty() {
        return Ok(String::new()); // not an IWK customer — no card
    }

    // Billed / paid / outstanding across all the customer's bills.
    let s = vortex_plugin_sdk::sqlx::query(
        "SELECT to_char(COALESCE(SUM(total),0),'FM999,999,990.00') AS billed, \
                to_char(COALESCE(SUM(payments),0),'FM999,999,990.00') AS paid, \
                to_char(COALESCE(SUM(total - payments),0),'FM999,999,990.00') AS outstanding \
         FROM iwk_bill WHERE contact_id = $1 AND record_state <> 'cancelled'",
    )
    .bind(contact_id)
    .fetch_one(db)
    .await
    .map_err(|e| e.to_string())?;
    let billed: String = s.try_get("billed").ok().flatten().unwrap_or_default();
    let paid: String = s.try_get("paid").ok().flatten().unwrap_or_default();
    let outstanding: String = s.try_get("outstanding").ok().flatten().unwrap_or_default();

    let mut acct_rows = String::new();
    for a in &accounts {
        let id: Uuid = match a.try_get("id") { Ok(v) => v, Err(_) => continue };
        let no: String = a.try_get("account_no").unwrap_or_default();
        let cat: String = a.try_get("category").unwrap_or_default();
        let sys: String = a.try_get("system_type").unwrap_or_default();
        let status: String = a.try_get("status").unwrap_or_default();
        let nb: String = a.try_get("nb").ok().flatten().unwrap_or_default();
        let credit: String = a.try_get("credit").ok().flatten().unwrap_or_default();
        let badge = match status.as_str() { "suspended" => "badge-warning", "terminated" => "badge-error", _ => "badge-success" };
        acct_rows.push_str(&format!(
            "<tr class=\"hover cursor-pointer\" onclick=\"location.href='/iwk/accounts/{id}'\">\
             <td class=\"font-mono text-xs\">{no}</td><td>{cat} / {sys}</td>\
             <td><span class=\"badge {badge} badge-sm\">{status}</span></td><td>{nb}</td>\
             <td class=\"text-right font-mono\">RM {credit}</td></tr>",
            id = id, no = esc(&no), cat = esc(&cat), sys = esc(&sys),
            badge = badge, status = esc(&status), nb = esc(&nb), credit = esc(&credit),
        ));
    }

    Ok(format!(
        r##"<div class="flex items-center justify-between mb-3">
  <div class="flex gap-4 text-sm">
    <div><span class="opacity-60">Billed:</span> <b>RM {billed}</b></div>
    <div><span class="opacity-60">Paid:</span> <b>RM {paid}</b></div>
    <div><span class="opacity-60">Outstanding:</span> <b>RM {outstanding}</b></div>
  </div>
  <div class="flex gap-2">
    <a href="/iwk/accounts/new?contact={contact_id}" class="btn btn-sm btn-outline">Open another account</a>
    <a href="/iwk/customers/{contact_id}" class="btn btn-sm btn-primary">Customer ledger →</a>
  </div>
</div>
<table class="table table-sm">
  <thead><tr><th>Account</th><th>Type</th><th>Status</th><th>Next bill</th><th class="text-right">Credit</th></tr></thead>
  <tbody>{acct_rows}</tbody>
</table>"##,
        billed = billed, paid = paid, outstanding = outstanding,
        contact_id = contact_id, acct_rows = acct_rows,
    ))
}

/// One posted movement on the customer ledger.
pub struct LedgerEntry {
    pub date: String,
    pub kind: String,        // "bill" | "payment"
    pub reference: String,
    pub account_no: String,
    pub debit: Decimal,
    pub credit: Decimal,
    pub balance: Decimal,    // running
}

/// The customer's full ledger: bills (debit) and payments (credit) across all
/// their accounts, chronological, with a running balance (positive = owing).
pub async fn customer_ledger(db: &PgPool, contact_id: Uuid) -> Result<Vec<LedgerEntry>, String> {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT dt, kind, reference, account_no, debit, credit FROM ( \
            SELECT b.bill_date AS dt, 'bill' AS kind, b.bill_no AS reference, b.account_no, \
                   b.total AS debit, 0::numeric AS credit \
            FROM iwk_bill b WHERE b.contact_id = $1 AND b.record_state <> 'cancelled' \
            UNION ALL \
            SELECT p.payment_date, 'payment', p.payment_no, a.account_no, 0::numeric, p.amount \
            FROM iwk_payment p JOIN iwk_account a ON a.id = p.account_id WHERE p.contact_id = $1 \
         ) t ORDER BY dt ASC, kind ASC",
    )
    .bind(contact_id)
    .fetch_all(db)
    .await
    .map_err(|e| e.to_string())?;

    let mut balance = Decimal::ZERO;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let debit: Decimal = r.try_get("debit").unwrap_or_default();
        let credit: Decimal = r.try_get("credit").unwrap_or_default();
        balance += debit - credit;
        let dt: chrono::NaiveDate = r.try_get("dt").map_err(|e| e.to_string())?;
        out.push(LedgerEntry {
            date: dt.format("%d/%m/%Y").to_string(),
            kind: r.try_get("kind").unwrap_or_default(),
            reference: r.try_get("reference").ok().flatten().unwrap_or_default(),
            account_no: r.try_get("account_no").unwrap_or_default(),
            debit,
            credit,
            balance,
        });
    }
    Ok(out)
}
