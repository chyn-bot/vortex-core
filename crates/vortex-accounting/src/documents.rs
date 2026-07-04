//! AR/AP document layer — invoices, bills, credit notes, payments.
//!
//! A document is an `acc_move` whose `move_type` is not `entry`, carrying
//! commercial lines in `acc_invoice_line`. Posting expands those lines into
//! balanced GL lines (receivable/payable ↔ income/expense ↔ tax) and then
//! goes through the same [`crate::service::post_move`] engine as any manual
//! entry. Payments are moves too; [`register_payment`] posts the payment and
//! allocates it against open documents via `acc_partial_reconcile`.
//!
//! ```rust,ignore
//! // What an adopting module (e.g. highway tenancy billing) calls:
//! let inv = documents::create_invoice(&db, user.id, &NewInvoice {
//!     move_type: "customer_invoice",
//!     partner_id: tenant_contact,
//!     invoice_date: today,
//!     due_date: Some(today + Duration::days(7)),
//!     journal_code: None,             // defaults by type (SAL)
//!     currency_id,
//!     origin_ref: Some("hwy_tenancy_charge:…"),
//!     narration: None,
//!     company_id,
//!     lines: vec![InvoiceLine::new("Rent 2026-07", dec!(1), dec!(3500.00))],
//! }).await?;
//! let number = documents::post_invoice(&db, &state.pool, inv, user.id).await?;
//! // …later, when the tenant pays:
//! documents::register_payment(&db, &state.pool, user.id, &NewPayment {
//!     partner_id: tenant_contact,
//!     direction: PaymentDirection::Inbound,
//!     journal_code: "BNK",
//!     currency_code: None,
//!     amount: dec!(3500.00),
//!     payment_date: today,
//!     memo: Some("TNC/2026/00007 July rent"),
//!     company_id,
//!     allocate_to: vec![inv],
//! }).await?;
//! ```
//!
//! v1 scope: company-currency amounts; exclusive **and** inclusive percent
//! taxes plus fixed taxes (via commerce `compute_tax_amount`); no
//! multi-currency revaluation; no compound taxes.

use vortex_plugin_sdk::chrono::NaiveDate;
use vortex_plugin_sdk::common::{VortexError, VortexResult};
use vortex_plugin_sdk::orm::commerce::{compute_tax_amount, Tax, TaxAmountType, TaxTypeUse};
use vortex_plugin_sdk::orm::ConnectionPool;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use crate::service;

// ─── Inputs ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InvoiceLine {
    pub description: String,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    pub tax_id: Option<Uuid>,
    /// Income (customer docs) / expense (vendor docs) account override.
    pub account_id: Option<Uuid>,
}

impl InvoiceLine {
    pub fn new(description: &str, quantity: Decimal, unit_price: Decimal) -> Self {
        Self {
            description: description.to_string(),
            quantity,
            unit_price,
            tax_id: None,
            account_id: None,
        }
    }

    pub fn with_tax(mut self, tax_id: Uuid) -> Self {
        self.tax_id = Some(tax_id);
        self
    }

    pub fn with_account(mut self, account_id: Uuid) -> Self {
        self.account_id = Some(account_id);
        self
    }
}

#[derive(Debug, Clone)]
pub struct NewInvoice<'a> {
    /// `customer_invoice` | `customer_credit_note` | `vendor_bill`
    /// | `vendor_credit_note`
    pub move_type: &'a str,
    pub partner_id: Uuid,
    pub invoice_date: NaiveDate,
    pub due_date: Option<NaiveDate>,
    /// Defaults per type: customer docs → SAL, vendor docs → PUR.
    pub journal_code: Option<&'a str>,
    pub currency_id: Option<Uuid>,
    pub origin_ref: Option<&'a str>,
    pub narration: Option<&'a str>,
    pub company_id: Option<Uuid>,
    pub lines: Vec<InvoiceLine>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentDirection {
    /// Money in — settles customer invoices (credit AR, debit bank/cash).
    Inbound,
    /// Money out — settles vendor bills (debit AP, credit bank/cash).
    Outbound,
}

#[derive(Debug, Clone)]
pub struct NewPayment<'a> {
    pub partner_id: Uuid,
    pub direction: PaymentDirection,
    /// A bank or cash journal code, e.g. `"BNK"`.
    pub journal_code: &'a str,
    /// Payment currency code (None or "MYR" = company currency). FX
    /// payments allocate against documents of the SAME currency; the
    /// MYR difference posts automatically as realized gain/loss.
    pub currency_code: Option<&'a str>,
    pub amount: Decimal,
    pub payment_date: NaiveDate,
    pub memo: Option<&'a str>,
    pub company_id: Option<Uuid>,
    /// Posted, unpaid document move ids to allocate against (in order).
    /// Any unallocated remainder stays on the payment as an open credit.
    pub allocate_to: Vec<Uuid>,
}

// ─── Helpers ─────────────────────────────────────────────────────────────

fn is_customer_doc(move_type: &str) -> bool {
    matches!(move_type, "customer_invoice" | "customer_credit_note")
}

fn is_document(move_type: &str) -> bool {
    matches!(
        move_type,
        "customer_invoice" | "customer_credit_note" | "vendor_bill" | "vendor_credit_note"
    )
}

async fn load_tax(db: &PgPool, tax_id: Uuid) -> VortexResult<Option<Tax>> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, description, amount_type, amount, type_tax_use, price_include, active \
         FROM taxes WHERE id = $1",
    )
    .bind(tax_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(row.map(|r| {
        let amount_type: String = r.get("amount_type");
        let type_tax_use: String = r.get("type_tax_use");
        Tax {
            id: r.get("id"),
            name: r.get("name"),
            description: r.try_get("description").ok(),
            amount_type: if amount_type == "fixed" {
                TaxAmountType::Fixed
            } else {
                TaxAmountType::Percent
            },
            amount: r.get("amount"),
            type_tax_use: match type_tax_use.as_str() {
                "sale" => TaxTypeUse::Sale,
                "purchase" => TaxTypeUse::Purchase,
                _ => TaxTypeUse::None,
            },
            price_include: r.get("price_include"),
            active: r.get("active"),
        }
    }))
}

/// Per-line and total amounts for a document: `(untaxed, tax, total)`.
async fn compute_document_totals(
    db: &PgPool,
    lines: &[(Decimal, Decimal, Option<Uuid>)], // (quantity, unit_price, tax_id)
) -> VortexResult<(Decimal, Decimal, Decimal)> {
    let mut untaxed = Decimal::ZERO;
    let mut tax_total = Decimal::ZERO;
    for (quantity, unit_price, tax_id) in lines {
        let gross = (*quantity * *unit_price).round_dp(2);
        match tax_id {
            Some(tid) => {
                let Some(tax) = load_tax(db, *tid).await? else {
                    return Err(VortexError::ValidationFailed(format!(
                        "tax {tid} not found"
                    )));
                };
                let comp = compute_tax_amount(gross, &tax);
                untaxed += comp.base.round_dp(2);
                tax_total += comp.tax.round_dp(2);
            }
            None => untaxed += gross,
        }
    }
    Ok((
        untaxed.round_dp(2),
        tax_total.round_dp(2),
        (untaxed + tax_total).round_dp(2),
    ))
}

// ─── Documents ───────────────────────────────────────────────────────────

/// Create a draft invoice/bill/credit note with its commercial lines and
/// computed totals. Returns the move id. GL lines are generated at posting.
pub async fn create_invoice(
    db: &PgPool,
    user_id: Uuid,
    inv: &NewInvoice<'_>,
) -> VortexResult<Uuid> {
    if !is_document(inv.move_type) {
        return Err(VortexError::ValidationFailed(format!(
            "'{}' is not a document move type",
            inv.move_type
        )));
    }
    if inv.lines.is_empty() {
        return Err(VortexError::ValidationFailed(
            "a document needs at least one line".to_string(),
        ));
    }
    let journal_code = inv.journal_code.unwrap_or(if is_customer_doc(inv.move_type) {
        "SAL"
    } else {
        "PUR"
    });
    let Some((journal_id, _)) = service::journal_by_code(db, inv.company_id, journal_code).await?
    else {
        return Err(VortexError::ValidationFailed(format!(
            "unknown journal code '{journal_code}'"
        )));
    };

    let amounts: Vec<(Decimal, Decimal, Option<Uuid>)> = inv
        .lines
        .iter()
        .map(|l| (l.quantity, l.unit_price, l.tax_id))
        .collect();
    let (untaxed, tax, total) = compute_document_totals(db, &amounts).await?;
    if total <= Decimal::ZERO {
        return Err(VortexError::ValidationFailed(
            "document total must be positive".to_string(),
        ));
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let move_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_move \
            (journal_id, move_date, move_type, partner_id, invoice_date, due_date, \
             currency_id, narration, origin_ref, untaxed_amount, tax_amount, total_amount, \
             company_id, created_by, updated_by) \
         VALUES ($1, $2, $3, $4, $2, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13) \
         RETURNING id",
    )
    .bind(journal_id)
    .bind(inv.invoice_date)
    .bind(inv.move_type)
    .bind(inv.partner_id)
    .bind(inv.due_date)
    .bind(inv.currency_id)
    .bind(inv.narration)
    .bind(inv.origin_ref)
    .bind(untaxed)
    .bind(tax)
    .bind(total)
    .bind(inv.company_id)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    for (i, line) in inv.lines.iter().enumerate() {
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO acc_invoice_line \
                (move_id, sequence, description, quantity, unit_price, tax_id, account_id, company_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(move_id)
        .bind(((i + 1) * 10) as i32)
        .bind(&line.description)
        .bind(line.quantity)
        .bind(line.unit_price)
        .bind(line.tax_id)
        .bind(line.account_id)
        .bind(inv.company_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }

    tx.commit()
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(move_id)
}

/// Recompute a draft document's totals from its lines (call after the UI
/// adds/removes lines). No-op for posted documents.
pub async fn refresh_document_totals(db: &PgPool, move_id: Uuid) -> VortexResult<()> {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT l.quantity, l.unit_price, l.tax_id \
         FROM acc_invoice_line l JOIN acc_move m ON m.id = l.move_id \
         WHERE l.move_id = $1 AND m.state = 'draft'",
    )
    .bind(move_id)
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    if rows.is_empty() {
        // No draft lines — zero the totals for an emptied draft, or a
        // posted/missing move (where the UPDATE below matches nothing).
    }
    let amounts: Vec<(Decimal, Decimal, Option<Uuid>)> = rows
        .iter()
        .map(|r| (r.get("quantity"), r.get("unit_price"), r.get("tax_id")))
        .collect();
    let (untaxed, tax, total) = compute_document_totals(db, &amounts).await?;
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_move SET untaxed_amount = $2, tax_amount = $3, total_amount = $4 \
         WHERE id = $1 AND state = 'draft'",
    )
    .bind(move_id)
    .bind(untaxed)
    .bind(tax)
    .bind(total)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(())
}

/// Post a draft document: expand its commercial lines into balanced GL
/// lines, then run the standard posting engine. Returns the number.
///
/// Expansion (customer invoice; credit notes and vendor docs mirror it):
/// - one receivable **debit** for the total, on the partner;
/// - one income **credit** per line (line account → config default);
/// - one tax **credit** for the tax total (config tax account).
pub async fn post_invoice(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    move_id: Uuid,
    user_id: Uuid,
) -> VortexResult<String> {
    let Some(head) = vortex_plugin_sdk::sqlx::query(
        "SELECT state, move_type, partner_id, company_id, total_amount, tax_amount \
         FROM acc_move WHERE id = $1",
    )
    .bind(move_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?
    else {
        return Err(VortexError::ValidationFailed("document not found".to_string()));
    };
    let state: String = head.get("state");
    let move_type: String = head.get("move_type");
    if state != "draft" {
        return Err(VortexError::ValidationFailed(format!(
            "only draft documents can be posted (state is '{state}')"
        )));
    }
    if !is_document(&move_type) {
        return Err(VortexError::ValidationFailed(
            "not a document — post plain entries with service::post_move".to_string(),
        ));
    }
    let partner_id: Option<Uuid> = head.get("partner_id");
    let company_id: Option<Uuid> = head.get("company_id");

    // Refresh totals from lines, then load them back.
    refresh_document_totals(db, move_id).await?;
    let totals = vortex_plugin_sdk::sqlx::query(
        "SELECT untaxed_amount, tax_amount, total_amount FROM acc_move WHERE id = $1",
    )
    .bind(move_id)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let total_amount: Decimal = totals.get("total_amount");
    if total_amount <= Decimal::ZERO {
        return Err(VortexError::ValidationFailed(
            "document total must be positive".to_string(),
        ));
    }

    let customer = is_customer_doc(&move_type);
    let credit_note = move_type.ends_with("credit_note");

    // Credit control (policy-configured): block or warn on customer
    // invoices that push the partner past their limit.
    if move_type == "customer_invoice" {
        if let Some(pid) = partner_id {
            if let Some(warning) =
                crate::banking::check_credit_limit(db, pid, total_amount).await?
            {
                vortex_plugin_sdk::tracing::warn!("credit control: {warning}");
            }
        }
    }
    // Which side of the balance sheet the counterpart sits on, and which
    // side of each GL line gets the amount. Customer invoice: AR debit /
    // income credit. Vendor bill: AP credit / expense debit. Credit notes
    // flip their parent document.
    let counterpart_role = if customer { "receivable" } else { "payable" };
    let line_role = if customer { "income" } else { "expense" };
    let counterpart_is_debit = customer ^ credit_note;

    let Some(counterpart_account) = service::default_account(db, company_id, counterpart_role).await?
    else {
        return Err(VortexError::ValidationFailed(format!(
            "no {counterpart_role} account configured — set one in acc_config or the chart"
        )));
    };
    let default_line_account = service::default_account(db, company_id, line_role).await?;

    // Wipe any previously generated GL lines (re-post attempt after a fix),
    // then expand fresh. Only drafts reach this point, so deletes are legal.
    vortex_plugin_sdk::sqlx::query("DELETE FROM acc_move_line WHERE move_id = $1")
        .bind(move_id)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let doc_lines = vortex_plugin_sdk::sqlx::query(
        "SELECT description, quantity, unit_price, tax_id, account_id \
         FROM acc_invoice_line WHERE move_id = $1 ORDER BY sequence",
    )
    .bind(move_id)
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    // Multi-currency: header totals stay in document currency; GL
    // debit/credit are MYR at the invoice-date rate; each line carries
    // its signed amount_currency. Company-currency docs pass through
    // with rate 1 and NULL currency columns.
    let currency_row = vortex_plugin_sdk::sqlx::query(
        "SELECT c.id, c.code FROM acc_move m JOIN currencies c ON c.id = m.currency_id \
         WHERE m.id = $1",
    )
    .bind(move_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let (fx_currency, fx_rate): (Option<Uuid>, Decimal) = match currency_row {
        Some(r) => {
            let code: String = r.get("code");
            if code == "MYR" {
                (None, Decimal::ONE)
            } else {
                let invoice_date: NaiveDate = vortex_plugin_sdk::sqlx::query_scalar(
                    "SELECT COALESCE(invoice_date, move_date) FROM acc_move WHERE id = $1",
                )
                .bind(move_id)
                .fetch_one(db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                (Some(r.get("id")), crate::currency::myr_rate(db, &code, invoice_date).await?)
            }
        }
        None => (None, Decimal::ONE),
    };
    let conv = |amount: Decimal| crate::currency::to_myr(amount, fx_rate);
    // Signed amount_currency: positive on the debit side.
    let signed = |amount: Decimal, is_debit: bool| if is_debit { amount } else { -amount };

    let mut seq = 10i32;
    // (account, partner, name, debit, credit, tax_id, tax_base_amount, amount_currency)
    type GlLine =
        (Uuid, Option<Uuid>, String, Decimal, Decimal, Option<Uuid>, Option<Decimal>, Option<Decimal>);
    let mut insert_line = Vec::<GlLine>::new();
    // Counterpart MYR = sum of the converted component lines so the
    // move balances exactly regardless of per-line rounding.
    let mut counterpart_myr = Decimal::ZERO;

    // 1) counterpart (AR/AP) placeholder — amounts patched below
    insert_line.push((
        counterpart_account,
        partner_id,
        move_type.replace('_', " "),
        Decimal::ZERO,
        Decimal::ZERO,
        None,
        None,
        fx_currency.map(|_| signed(total_amount, counterpart_is_debit)),
    ));

    // 2) one income/expense line per document line (net of tax), while
    //    collecting (gross, tax) pairs for the per-tax aggregation
    let mut taxes_by_id: std::collections::BTreeMap<Uuid, Tax> = Default::default();
    let mut taxed_lines: Vec<(Decimal, Option<Uuid>)> = Vec::new();
    for row in &doc_lines {
        let description: String = row.get("description");
        let quantity: Decimal = row.get("quantity");
        let unit_price: Decimal = row.get("unit_price");
        let tax_id: Option<Uuid> = row.get("tax_id");
        let account_override: Option<Uuid> = row.get("account_id");

        let gross = (quantity * unit_price).round_dp(2);
        let base = match tax_id {
            Some(tid) => {
                if !taxes_by_id.contains_key(&tid) {
                    let Some(tax) = load_tax(db, tid).await? else {
                        return Err(VortexError::ValidationFailed(format!("tax {tid} not found")));
                    };
                    taxes_by_id.insert(tid, tax);
                }
                compute_tax_amount(gross, &taxes_by_id[&tid]).base.round_dp(2)
            }
            None => gross,
        };
        taxed_lines.push((gross, tax_id));
        let Some(account) = account_override.or(default_line_account) else {
            return Err(VortexError::ValidationFailed(format!(
                "no {line_role} account for line '{description}' — set one on the line or in acc_config"
            )));
        };
        let base_myr = conv(base);
        counterpart_myr += base_myr;
        insert_line.push((
            account,
            None,
            description,
            if counterpart_is_debit { Decimal::ZERO } else { base_myr },
            if counterpart_is_debit { base_myr } else { Decimal::ZERO },
            None,
            None,
            fx_currency.map(|_| signed(base, !counterpart_is_debit)),
        ));
    }

    // 3) one GL tax line PER DISTINCT TAX, carrying tax_id and the
    //    taxable base — SST-02 and e-invoice tax blocks read these
    //    lines directly, so the return can never drift from the GL.
    let tax_inputs: Vec<(Decimal, Option<&Tax>)> = taxed_lines
        .iter()
        .map(|(gross, tid)| (*gross, tid.as_ref().and_then(|t| taxes_by_id.get(t))))
        .collect();
    for bucket in crate::tax::aggregate_by_tax(&tax_inputs) {
        if bucket.tax.is_zero() {
            continue; // zero-rated/exempt: base tracked on doc lines, no GL tax line
        }
        let Some(tax_acc) = crate::tax::tax_account_for(db, company_id, bucket.tax_id).await?
        else {
            return Err(VortexError::ValidationFailed(format!(
                "no tax account configured for '{}' — set acc_tax_config or acc_config",
                bucket.tax_name
            )));
        };
        let tax_myr = conv(bucket.tax);
        counterpart_myr += tax_myr;
        insert_line.push((
            tax_acc,
            None,
            bucket.tax_name.clone(),
            if counterpart_is_debit { Decimal::ZERO } else { tax_myr },
            if counterpart_is_debit { tax_myr } else { Decimal::ZERO },
            Some(bucket.tax_id),
            Some(bucket.base),
            fx_currency.map(|_| signed(bucket.tax, !counterpart_is_debit)),
        ));
    }

    // Patch the counterpart with the summed MYR value.
    if counterpart_is_debit {
        insert_line[0].3 = counterpart_myr;
    } else {
        insert_line[0].4 = counterpart_myr;
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    for (account, line_partner, name, debit, credit, line_tax, tax_base, amount_currency) in
        insert_line
    {
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO acc_move_line \
                (move_id, sequence, account_id, partner_id, name, debit, credit, company_id, \
                 tax_id, tax_base_amount, currency_id, amount_currency) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(move_id)
        .bind(seq)
        .bind(account)
        .bind(line_partner)
        .bind(&name)
        .bind(debit)
        .bind(credit)
        .bind(company_id)
        .bind(line_tax)
        .bind(tax_base)
        .bind(fx_currency)
        .bind(amount_currency)
        .execute(&mut *tx)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        seq += 10;
    }
    // Fix the posting rate while still draft (immutable once posted).
    if fx_currency.is_some() {
        vortex_plugin_sdk::sqlx::query(
            "UPDATE acc_move SET currency_rate = $2 WHERE id = $1",
        )
        .bind(move_id)
        .bind(fx_rate)
        .execute(&mut *tx)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }
    tx.commit()
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    // Hand over to the standard posting engine (balance, lock date, number,
    // amount_residual = total for documents).
    let number = service::post_move(db, seq_pool, move_id, user_id).await?;

    // FX documents: MYR residual is the converted counterpart; the
    // document-currency residual drives settlement. Both columns are
    // on the guard's mutable allow-list.
    if fx_currency.is_some() {
        vortex_plugin_sdk::sqlx::query(
            "UPDATE acc_move SET amount_residual = $2, amount_residual_currency = $3 \
             WHERE id = $1",
        )
        .bind(move_id)
        .bind(counterpart_myr)
        .bind(total_amount)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }
    Ok(number)
}

// ─── Payments & reconciliation ───────────────────────────────────────────

/// The open (unreconciled) receivable/payable GL line of a posted document.
pub(crate) async fn open_counterpart_line(
    db: &PgPool,
    document_move_id: Uuid,
) -> VortexResult<Option<(Uuid, Decimal, bool)>> {
    // (line_id, open_amount, line_is_debit)
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, l.debit, l.credit, \
                COALESCE((SELECT SUM(pr.amount) FROM acc_partial_reconcile pr \
                          WHERE pr.debit_line_id = l.id OR pr.credit_line_id = l.id), 0) AS settled \
         FROM acc_move_line l \
         JOIN acc_account a ON a.id = l.account_id \
         WHERE l.move_id = $1 AND a.reconcile \
         ORDER BY l.sequence LIMIT 1",
    )
    .bind(document_move_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(row.map(|r| {
        let debit: Decimal = r.get("debit");
        let credit: Decimal = r.get("credit");
        let settled: Decimal = r.get("settled");
        let is_debit = !debit.is_zero();
        let gross = if is_debit { debit } else { credit };
        ((r.get("id")), (gross - settled).round_dp(2), is_debit)
    }))
}

/// Recompute a document's residual / payment_state from its reconciliations.
pub async fn refresh_payment_state(db: &PgPool, document_move_id: Uuid) -> VortexResult<()> {
    let Some((line_id, mut open, _)) = open_counterpart_line(db, document_move_id).await? else {
        return Ok(());
    };
    let head = vortex_plugin_sdk::sqlx::query(
        "SELECT total_amount, currency_rate FROM acc_move WHERE id = $1",
    )
    .bind(document_move_id)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let total: Decimal = head.get("total_amount");
    let fx_rate: Option<Decimal> = head.get("currency_rate");

    // FX documents settle in DOCUMENT currency: residual comes from the
    // partial reconciles' currency amounts, with the MYR residual
    // derived at the booked rate for display/reports.
    if let Some(rate) = fx_rate {
        let settled_cur: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT COALESCE(SUM(debit_amount_currency), 0) FROM acc_partial_reconcile \
             WHERE debit_line_id = $1 OR credit_line_id = $1",
        )
        .bind(line_id)
        .fetch_one(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        // `total` is already in document currency for FX documents.
        let open_cur = (total - settled_cur).max(Decimal::ZERO);
        open = crate::currency::to_myr(open_cur, rate);
        let payment_state = if open_cur <= Decimal::ZERO {
            "paid"
        } else if open_cur < total {
            "partial"
        } else {
            "not_paid"
        };
        vortex_plugin_sdk::sqlx::query(
            "UPDATE acc_move SET amount_residual = $2, amount_residual_currency = $3, \
                    payment_state = $4 WHERE id = $1",
        )
        .bind(document_move_id)
        .bind(open.max(Decimal::ZERO))
        .bind(open_cur)
        .bind(payment_state)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        if open_cur <= Decimal::ZERO {
            vortex_plugin_sdk::sqlx::query(
                "UPDATE acc_move_line l SET reconciled = TRUE \
                 FROM acc_account a \
                 WHERE l.move_id = $1 AND a.id = l.account_id AND a.reconcile",
            )
            .bind(document_move_id)
            .execute(db)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        }
        return Ok(());
    }

    let payment_state = if open <= Decimal::ZERO {
        "paid"
    } else if open < total {
        "partial"
    } else {
        "not_paid"
    };
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_move SET amount_residual = $2, payment_state = $3 WHERE id = $1",
    )
    .bind(document_move_id)
    .bind(open.max(Decimal::ZERO))
    .bind(payment_state)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    if open <= Decimal::ZERO {
        // Flag the counterpart line fully reconciled (trigger allow-list).
        vortex_plugin_sdk::sqlx::query(
            "UPDATE acc_move_line l SET reconciled = TRUE \
             FROM acc_account a \
             WHERE l.move_id = $1 AND a.id = l.account_id AND a.reconcile",
        )
        .bind(document_move_id)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }
    Ok(())
}

/// Register a payment: post the payment move (bank/cash ↔ AR/AP) and
/// allocate it against the given open documents in order. Returns the
/// payment's move id.
pub async fn register_payment(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    pay: &NewPayment<'_>,
) -> VortexResult<Uuid> {
    if pay.amount <= Decimal::ZERO {
        return Err(VortexError::ValidationFailed(
            "payment amount must be positive".to_string(),
        ));
    }
    let inbound = pay.direction == PaymentDirection::Inbound;

    // Liquidity account: the journal's default account, else cash/bank type.
    let Some((journal_id, journal_type)) =
        service::journal_by_code(db, pay.company_id, pay.journal_code).await?
    else {
        return Err(VortexError::ValidationFailed(format!(
            "unknown journal code '{}'",
            pay.journal_code
        )));
    };
    if journal_type != "bank" && journal_type != "cash" {
        return Err(VortexError::ValidationFailed(
            "payments go through a bank or cash journal".to_string(),
        ));
    }
    let liquidity: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT default_account_id FROM acc_journal WHERE id = $1",
    )
    .bind(journal_id)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let liquidity = match liquidity {
        Some(a) => a,
        None => service::account_by_type(
            db,
            pay.company_id,
            if journal_type == "bank" { "asset_bank" } else { "asset_cash" },
        )
        .await?
        .ok_or_else(|| {
            VortexError::ValidationFailed("no bank/cash account configured".to_string())
        })?,
    };
    let counterpart_role = if inbound { "receivable" } else { "payable" };
    let Some(counterpart) = service::default_account(db, pay.company_id, counterpart_role).await?
    else {
        return Err(VortexError::ValidationFailed(format!(
            "no {counterpart_role} account configured"
        )));
    };

    // FX: convert to MYR at the payment-date rate; lines carry the
    // signed document-currency amounts.
    let fx = match pay.currency_code {
        Some(code) if code != "MYR" => {
            let currency_id: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT id FROM currencies WHERE code = $1 AND active",
            )
            .bind(code)
            .fetch_optional(db)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
            let Some(currency_id) = currency_id else {
                return Err(VortexError::ValidationFailed(format!("unknown currency {code}")));
            };
            let rate = crate::currency::myr_rate(db, code, pay.payment_date).await?;
            Some((currency_id, rate))
        }
        _ => None,
    };
    let amount_myr = match fx {
        Some((_, rate)) => crate::currency::to_myr(pay.amount, rate),
        None => pay.amount,
    };
    let with_ccy = |line: service::MoveLine, signed_amount: Decimal| match fx {
        Some((cid, _)) => line.with_currency(cid, signed_amount),
        None => line,
    };

    // Inbound: debit bank, credit AR. Outbound: debit AP, credit bank.
    let memo = pay.memo.unwrap_or("Payment");
    let lines = if inbound {
        vec![
            with_ccy(service::MoveLine::debit(liquidity, amount_myr, Some(memo)), pay.amount),
            with_ccy(
                service::MoveLine::credit(counterpart, amount_myr, Some(memo))
                    .with_partner(pay.partner_id),
                -pay.amount,
            ),
        ]
    } else {
        vec![
            with_ccy(
                service::MoveLine::debit(counterpart, amount_myr, Some(memo))
                    .with_partner(pay.partner_id),
                pay.amount,
            ),
            with_ccy(service::MoveLine::credit(liquidity, amount_myr, Some(memo)), -pay.amount),
        ]
    };

    let (payment_id, _number) = service::create_and_post(
        db,
        seq_pool,
        user_id,
        &service::NewMove {
            journal_code: pay.journal_code,
            move_date: pay.payment_date,
            move_type: "payment",
            ref_: pay.memo,
            narration: None,
            partner_id: Some(pay.partner_id),
            origin_ref: None,
            company_id: pay.company_id,
            lines,
        },
    )
    .await?;

    // The payment's counterpart line (the AR credit / AP debit).
    let Some((payment_line_id, mut payment_open, payment_is_debit)) =
        open_counterpart_line(db, payment_id).await?
    else {
        return Err(VortexError::ValidationFailed(
            "payment posted without a reconcilable line — check the chart".to_string(),
        ));
    };

    // Allocate oldest-first across the requested documents. FX
    // payments match in DOCUMENT currency against same-currency
    // documents; the MYR delta posts as realized gain/loss.
    let mut payment_open_currency = pay.amount;
    for doc_id in &pay.allocate_to {
        match fx {
            None => {
                if payment_open <= Decimal::ZERO {
                    break;
                }
                let Some((doc_line_id, doc_open, doc_is_debit)) =
                    open_counterpart_line(db, *doc_id).await?
                else {
                    continue;
                };
                if doc_open <= Decimal::ZERO || doc_is_debit == payment_is_debit {
                    continue;
                }
                // Company-currency docs only on this path.
                let doc_rate: Option<Decimal> = vortex_plugin_sdk::sqlx::query_scalar(
                    "SELECT currency_rate FROM acc_move WHERE id = $1",
                )
                .bind(*doc_id)
                .fetch_one(db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                if doc_rate.is_some() {
                    continue; // FX document needs an FX payment in its currency
                }
                let matched = payment_open.min(doc_open);
                let (debit_line, credit_line) = if doc_is_debit {
                    (doc_line_id, payment_line_id)
                } else {
                    (payment_line_id, doc_line_id)
                };
                vortex_plugin_sdk::sqlx::query(
                    "INSERT INTO acc_partial_reconcile \
                        (debit_line_id, credit_line_id, amount, company_id, created_by) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(debit_line)
                .bind(credit_line)
                .bind(matched)
                .bind(pay.company_id)
                .bind(user_id)
                .execute(db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                payment_open -= matched;
                refresh_payment_state(db, *doc_id).await?;
            }
            Some((currency_id, pay_rate)) => {
                if payment_open_currency <= Decimal::ZERO {
                    break;
                }
                let doc = vortex_plugin_sdk::sqlx::query(
                    "SELECT currency_id, currency_rate, amount_residual_currency, partner_id, \
                            company_id \
                     FROM acc_move WHERE id = $1 AND state = 'posted'",
                )
                .bind(*doc_id)
                .fetch_optional(db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                let Some(doc) = doc else { continue };
                if doc.get::<Option<Uuid>, _>("currency_id") != Some(currency_id) {
                    continue; // currency mismatch
                }
                let Some(doc_rate) = doc.get::<Option<Decimal>, _>("currency_rate") else {
                    continue;
                };
                let doc_open_cur: Decimal =
                    doc.get::<Option<Decimal>, _>("amount_residual_currency").unwrap_or_default();
                if doc_open_cur <= Decimal::ZERO {
                    continue;
                }
                let Some((doc_line_id, _, doc_is_debit)) =
                    open_counterpart_line(db, *doc_id).await?
                else {
                    continue;
                };
                if doc_is_debit == payment_is_debit {
                    continue;
                }
                let matched_cur = payment_open_currency.min(doc_open_cur);
                let doc_side_myr = crate::currency::to_myr(matched_cur, doc_rate);
                let (debit_line, credit_line) = if doc_is_debit {
                    (doc_line_id, payment_line_id)
                } else {
                    (payment_line_id, doc_line_id)
                };
                let pr_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
                    "INSERT INTO acc_partial_reconcile \
                        (debit_line_id, credit_line_id, amount, company_id, created_by, \
                         debit_amount_currency, credit_amount_currency) \
                     VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING id",
                )
                .bind(debit_line)
                .bind(credit_line)
                .bind(doc_side_myr)
                .bind(pay.company_id)
                .bind(user_id)
                .bind(matched_cur)
                .fetch_one(db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

                // Realized FX: settled-vs-booked MYR on the matched slice.
                // Inbound (AR): delta = settled − booked; outbound (AP)
                // needs the opposite sign to square the counterpart.
                let settled_myr = crate::currency::to_myr(matched_cur, pay_rate);
                let raw_delta = (settled_myr - doc_side_myr).round_dp(2);
                let delta = if inbound { raw_delta } else { -raw_delta };
                let doc_partner: Option<Uuid> = doc.get("partner_id");
                let doc_company: Option<Uuid> = doc.get("company_id");
                crate::currency::post_realized_fx(
                    db,
                    seq_pool,
                    user_id,
                    doc_company,
                    doc_partner,
                    counterpart,
                    pr_id,
                    delta,
                    pay.payment_date,
                )
                .await?;

                payment_open_currency -= matched_cur;
                refresh_payment_state(db, *doc_id).await?;
            }
        }
    }
    refresh_payment_state(db, payment_id).await?;

    Ok(payment_id)
}
