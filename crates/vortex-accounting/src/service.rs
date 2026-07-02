//! Public accounting service API — the surface other plugins adopt.
//!
//! The contract mirrors `vortex_inventory::post_move`: plain functions over
//! the tenant `PgPool` (plus the sequence pool for numbering), no `AppState`,
//! so any module — purchase bills, inventory valuation, a vertical's tenancy
//! billing — can post journal entries without knowing accounting internals.
//!
//! ```rust,ignore
//! use vortex_accounting::service::{self, MoveLine, NewMove};
//!
//! let (move_id, number) = service::create_and_post(
//!     &db, &state.pool, user.id,
//!     &NewMove {
//!         journal_code: "GEN",
//!         move_date: today,
//!         move_type: "entry",
//!         ref_: Some("WO/000042"),
//!         narration: Some("Parts consumed on work order"),
//!         partner_id: None,
//!         origin_ref: Some("maint_work_order:1234…"),
//!         company_id,
//!         lines: vec![
//!             MoveLine::debit(maintenance_expense, dec!(150), Some("Parts")),
//!             MoveLine::credit(inventory_account, dec!(150), Some("Parts")),
//!         ],
//!     },
//! ).await?;
//! ```
//!
//! Invariants enforced here (and by DB triggers in migration 001):
//! - a move posts only when Σdebit == Σcredit, with ≥ 2 lines and a
//!   non-zero total;
//! - posting on or before the company lock date is rejected;
//! - posted moves are immutable — corrections go through [`reverse_move`].

use vortex_plugin_sdk::chrono::NaiveDate;
use vortex_plugin_sdk::common::{VortexError, VortexResult};
use vortex_plugin_sdk::orm::sequence::{self, SequenceSpec};
use vortex_plugin_sdk::orm::ConnectionPool;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

// ─── Sequences (one per journal type, yearly scope) ──────────────────────

const SEQ_SALE: SequenceSpec =
    SequenceSpec::new("accounting.move.sale", "SAL").with_padding(5).yearly();
const SEQ_PURCHASE: SequenceSpec =
    SequenceSpec::new("accounting.move.purchase", "PUR").with_padding(5).yearly();
const SEQ_BANK: SequenceSpec =
    SequenceSpec::new("accounting.move.bank", "BNK").with_padding(5).yearly();
const SEQ_CASH: SequenceSpec =
    SequenceSpec::new("accounting.move.cash", "CSH").with_padding(5).yearly();
const SEQ_GENERAL: SequenceSpec =
    SequenceSpec::new("accounting.move.general", "GEN").with_padding(5).yearly();

/// The entry-number sequence for a journal type (`SAL/2026/00042`).
pub fn move_sequence_for(journal_type: &str) -> &'static SequenceSpec {
    match journal_type {
        "sale" => &SEQ_SALE,
        "purchase" => &SEQ_PURCHASE,
        "bank" => &SEQ_BANK,
        "cash" => &SEQ_CASH,
        _ => &SEQ_GENERAL,
    }
}

// ─── Inputs ──────────────────────────────────────────────────────────────

/// One journal-entry line. Exactly one of `debit` / `credit` should be
/// non-zero (the DB CHECK rejects lines set on both sides).
#[derive(Debug, Clone)]
pub struct MoveLine {
    pub account_id: Uuid,
    pub partner_id: Option<Uuid>,
    pub name: Option<String>,
    pub debit: Decimal,
    pub credit: Decimal,
}

impl MoveLine {
    pub fn debit(account_id: Uuid, amount: Decimal, name: Option<&str>) -> Self {
        Self {
            account_id,
            partner_id: None,
            name: name.map(str::to_string),
            debit: amount,
            credit: Decimal::ZERO,
        }
    }

    pub fn credit(account_id: Uuid, amount: Decimal, name: Option<&str>) -> Self {
        Self {
            account_id,
            partner_id: None,
            name: name.map(str::to_string),
            debit: Decimal::ZERO,
            credit: amount,
        }
    }

    pub fn with_partner(mut self, partner_id: Uuid) -> Self {
        self.partner_id = Some(partner_id);
        self
    }
}

/// A draft journal entry to create.
#[derive(Debug, Clone)]
pub struct NewMove<'a> {
    /// Journal code, e.g. `"GEN"`, `"SAL"` — must exist in `acc_journal`.
    pub journal_code: &'a str,
    pub move_date: NaiveDate,
    /// `entry` | `customer_invoice` | `customer_credit_note` | `vendor_bill`
    /// | `vendor_credit_note` | `payment`
    pub move_type: &'a str,
    /// External reference (a PO number, a tenancy charge ref, …).
    pub ref_: Option<&'a str>,
    pub narration: Option<&'a str>,
    pub partner_id: Option<Uuid>,
    /// Adopting-module back-reference, e.g. `hwy_tenancy_charge:<uuid>`.
    pub origin_ref: Option<&'a str>,
    pub company_id: Option<Uuid>,
    pub lines: Vec<MoveLine>,
}

// ─── Balance validation (pure, unit-tested) ──────────────────────────────

/// Validate that a line set can post: ≥ 2 lines, no negative side, and
/// Σdebit == Σcredit with a non-zero total (2-dp comparison — the storage
/// precision of `acc_move_line`).
pub fn validate_balanced(lines: &[(Decimal, Decimal)]) -> Result<Decimal, String> {
    if lines.len() < 2 {
        return Err("a journal entry needs at least two lines".to_string());
    }
    let mut debit_total = Decimal::ZERO;
    let mut credit_total = Decimal::ZERO;
    for (debit, credit) in lines {
        if debit.is_sign_negative() || credit.is_sign_negative() {
            return Err("line amounts cannot be negative".to_string());
        }
        if !debit.is_zero() && !credit.is_zero() {
            return Err("a line is either debit or credit, not both".to_string());
        }
        debit_total += debit;
        credit_total += credit;
    }
    let debit_total = debit_total.round_dp(2);
    let credit_total = credit_total.round_dp(2);
    if debit_total != credit_total {
        return Err(format!(
            "entry is unbalanced: debits {debit_total} ≠ credits {credit_total}"
        ));
    }
    if debit_total.is_zero() {
        return Err("entry total cannot be zero".to_string());
    }
    Ok(debit_total)
}

// ─── Lookups ─────────────────────────────────────────────────────────────

/// Resolve a journal by code (company-scoped row first, then the shared row).
pub async fn journal_by_code(
    db: &PgPool,
    company_id: Option<Uuid>,
    code: &str,
) -> VortexResult<Option<(Uuid, String)>> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT id, journal_type FROM acc_journal \
         WHERE active AND code = $1 AND (company_id = $2 OR company_id IS NULL) \
         ORDER BY company_id NULLS LAST LIMIT 1",
    )
    .bind(code)
    .bind(company_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(row.map(|r| (r.get("id"), r.get("journal_type"))))
}

/// Resolve an account by code.
pub async fn account_by_code(
    db: &PgPool,
    company_id: Option<Uuid>,
    code: &str,
) -> VortexResult<Option<Uuid>> {
    let id = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account \
         WHERE active AND code = $1 AND (company_id = $2 OR company_id IS NULL) \
         ORDER BY company_id NULLS LAST LIMIT 1",
    )
    .bind(code)
    .bind(company_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(id)
}

/// Resolve the default account for a role, config-first: the `acc_config`
/// row wins; otherwise the first active account of the matching type.
/// `role` ∈ receivable | payable | tax | income | expense.
pub async fn default_account(
    db: &PgPool,
    company_id: Option<Uuid>,
    role: &str,
) -> VortexResult<Option<Uuid>> {
    let config_col = match role {
        "receivable" => "receivable_account_id",
        "payable" => "payable_account_id",
        "tax" => "tax_account_id",
        "income" => "income_account_id",
        "expense" => "expense_account_id",
        other => {
            return Err(VortexError::ValidationFailed(format!(
                "unknown default-account role '{other}'"
            )))
        }
    };
    let sql = format!(
        "SELECT {config_col} FROM acc_config \
         WHERE company_id = $1 OR company_id IS NULL \
         ORDER BY company_id NULLS LAST LIMIT 1"
    );
    let from_config: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(&sql)
        .bind(company_id)
        .fetch_optional(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?
        .flatten();
    if from_config.is_some() {
        return Ok(from_config);
    }
    let account_type = match role {
        "receivable" => "asset_receivable",
        "payable" => "liability_payable",
        "tax" => "liability_current",
        "income" => "income",
        _ => "expense",
    };
    account_by_type(db, company_id, account_type).await
}

/// First active account of a given `account_type`.
pub async fn account_by_type(
    db: &PgPool,
    company_id: Option<Uuid>,
    account_type: &str,
) -> VortexResult<Option<Uuid>> {
    let id = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account \
         WHERE active AND account_type = $1 AND (company_id = $2 OR company_id IS NULL) \
         ORDER BY company_id NULLS LAST, code LIMIT 1",
    )
    .bind(account_type)
    .bind(company_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(id)
}

/// The company lock date (company row first, then shared row), if any.
pub async fn lock_date(db: &PgPool, company_id: Option<Uuid>) -> VortexResult<Option<NaiveDate>> {
    let date: Option<Option<NaiveDate>> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT lock_date FROM acc_config \
         WHERE company_id = $1 OR company_id IS NULL \
         ORDER BY company_id NULLS LAST LIMIT 1",
    )
    .bind(company_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(date.flatten())
}

// ─── Core API ────────────────────────────────────────────────────────────

/// Create a draft journal entry with its lines. Returns the move id.
/// Drafts may be unbalanced — balance is enforced at posting.
pub async fn create_move(db: &PgPool, user_id: Uuid, new: &NewMove<'_>) -> VortexResult<Uuid> {
    if new.lines.is_empty() {
        return Err(VortexError::ValidationFailed(
            "a journal entry needs at least one line".to_string(),
        ));
    }
    let Some((journal_id, _)) = journal_by_code(db, new.company_id, new.journal_code).await?
    else {
        return Err(VortexError::ValidationFailed(format!(
            "unknown journal code '{}'",
            new.journal_code
        )));
    };

    let mut tx = db
        .begin()
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let move_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_move \
            (journal_id, move_date, ref, narration, move_type, partner_id, \
             origin_ref, company_id, created_by, updated_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9) \
         RETURNING id",
    )
    .bind(journal_id)
    .bind(new.move_date)
    .bind(new.ref_)
    .bind(new.narration)
    .bind(new.move_type)
    .bind(new.partner_id)
    .bind(new.origin_ref)
    .bind(new.company_id)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    for (i, line) in new.lines.iter().enumerate() {
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO acc_move_line \
                (move_id, sequence, account_id, partner_id, name, debit, credit, company_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(move_id)
        .bind(((i + 1) * 10) as i32)
        .bind(line.account_id)
        .bind(line.partner_id.or(new.partner_id))
        .bind(line.name.as_deref())
        .bind(line.debit.round_dp(2))
        .bind(line.credit.round_dp(2))
        .bind(new.company_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }

    tx.commit()
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(move_id)
}

/// Post a draft entry: validate balance and lock date, mint the journal
/// number, flip to `posted`. Returns the assigned number.
pub async fn post_move(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    move_id: Uuid,
    user_id: Uuid,
) -> VortexResult<String> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let Some(head) = vortex_plugin_sdk::sqlx::query(
        "SELECT m.state, m.move_date, m.move_type, m.total_amount, m.company_id, \
                j.journal_type \
         FROM acc_move m JOIN acc_journal j ON j.id = m.journal_id \
         WHERE m.id = $1 FOR UPDATE OF m",
    )
    .bind(move_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?
    else {
        return Err(VortexError::ValidationFailed("journal entry not found".to_string()));
    };

    let state: String = head.get("state");
    if state != "draft" {
        return Err(VortexError::ValidationFailed(format!(
            "only draft entries can be posted (state is '{state}')"
        )));
    }
    let move_date: NaiveDate = head.get("move_date");
    let move_type: String = head.get("move_type");
    let company_id: Option<Uuid> = head.get("company_id");
    let journal_type: String = head.get("journal_type");

    // Lock date check
    if let Some(lock) = lock_date(db, company_id).await? {
        if move_date <= lock {
            return Err(VortexError::ValidationFailed(format!(
                "cannot post on {move_date}: books are locked through {lock}"
            )));
        }
    }

    // Balance check
    let line_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT debit, credit FROM acc_move_line WHERE move_id = $1",
    )
    .bind(move_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let amounts: Vec<(Decimal, Decimal)> = line_rows
        .iter()
        .map(|r| (r.get("debit"), r.get("credit")))
        .collect();
    let total = validate_balanced(&amounts).map_err(VortexError::ValidationFailed)?;

    // Mint the number last, after all validation, to keep gaps minimal.
    let number = sequence::next(seq_pool, move_sequence_for(&journal_type)).await?;

    // Documents (invoices/bills) start life owing their full total.
    let stored_total: Decimal = head.get("total_amount");
    let doc_total = if stored_total.is_zero() { total } else { stored_total };
    let residual = if move_type == "entry" { Decimal::ZERO } else { doc_total };

    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_move SET number = $2, state = 'posted', posted_by = $3, \
            posted_at = NOW(), updated_by = $3, amount_residual = $4, \
            total_amount = CASE WHEN move_type = 'entry' THEN total_amount ELSE $5 END \
         WHERE id = $1",
    )
    .bind(move_id)
    .bind(&number)
    .bind(user_id)
    .bind(residual)
    .bind(doc_total)
    .execute(&mut *tx)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(number)
}

/// Create a draft entry and post it in one call. Returns `(id, number)`.
pub async fn create_and_post(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    new: &NewMove<'_>,
) -> VortexResult<(Uuid, String)> {
    // Validate up front so we never leave a stray unbalanced draft behind.
    let amounts: Vec<(Decimal, Decimal)> =
        new.lines.iter().map(|l| (l.debit, l.credit)).collect();
    validate_balanced(&amounts).map_err(VortexError::ValidationFailed)?;
    let move_id = create_move(db, user_id, new).await?;
    let number = post_move(db, seq_pool, move_id, user_id).await?;
    Ok((move_id, number))
}

/// Reverse a posted entry: creates and posts a counter-entry (debits and
/// credits swapped) in the same journal, links it via `reversed_move_id`,
/// and marks the original `payment_state = 'reversed'`. Returns the
/// reversal's move id.
pub async fn reverse_move(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    move_id: Uuid,
    reversal_date: NaiveDate,
    user_id: Uuid,
) -> VortexResult<Uuid> {
    let Some(orig) = vortex_plugin_sdk::sqlx::query(
        "SELECT m.state, m.number, m.partner_id, m.company_id, m.origin_ref, j.code AS journal_code \
         FROM acc_move m JOIN acc_journal j ON j.id = m.journal_id WHERE m.id = $1",
    )
    .bind(move_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?
    else {
        return Err(VortexError::ValidationFailed("journal entry not found".to_string()));
    };
    let state: String = orig.get("state");
    if state != "posted" {
        return Err(VortexError::ValidationFailed(
            "only posted entries can be reversed".to_string(),
        ));
    }
    let number: Option<String> = orig.get("number");
    let number = number.unwrap_or_default();
    let journal_code: String = orig.get("journal_code");
    let partner_id: Option<Uuid> = orig.get("partner_id");
    let company_id: Option<Uuid> = orig.get("company_id");
    let origin_ref: Option<String> = orig.get("origin_ref");

    let line_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT account_id, partner_id, name, debit, credit \
         FROM acc_move_line WHERE move_id = $1 ORDER BY sequence",
    )
    .bind(move_id)
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let lines: Vec<MoveLine> = line_rows
        .iter()
        .map(|r| MoveLine {
            account_id: r.get("account_id"),
            partner_id: r.get("partner_id"),
            name: r.get("name"),
            // The reversal swaps sides.
            debit: r.get::<Decimal, _>("credit"),
            credit: r.get::<Decimal, _>("debit"),
        })
        .collect();

    let narration = format!("Reversal of {number}");
    let (reversal_id, _reversal_number) = create_and_post(
        db,
        seq_pool,
        user_id,
        &NewMove {
            journal_code: &journal_code,
            move_date: reversal_date,
            move_type: "entry",
            ref_: Some(&number),
            narration: Some(&narration),
            partner_id,
            origin_ref: origin_ref.as_deref(),
            company_id,
            lines,
        },
    )
    .await?;

    // Cross-link and flag the original. Both columns are on the posted-move
    // trigger allow-list.
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_move SET reversed_move_id = $2, updated_by = $3 WHERE id = $1",
    )
    .bind(reversal_id)
    .bind(move_id)
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_move SET payment_state = 'reversed', updated_by = $2 WHERE id = $1",
    )
    .bind(move_id)
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(reversal_id)
}

// ─── Tests (pure logic) ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn balanced_entry_passes() {
        let lines = vec![(dec!(150.00), Decimal::ZERO), (Decimal::ZERO, dec!(150.00))];
        assert_eq!(validate_balanced(&lines).unwrap(), dec!(150.00));
    }

    #[test]
    fn unbalanced_entry_fails() {
        let lines = vec![(dec!(150.00), Decimal::ZERO), (Decimal::ZERO, dec!(149.99))];
        assert!(validate_balanced(&lines).is_err());
    }

    #[test]
    fn single_line_fails() {
        let lines = vec![(dec!(150.00), Decimal::ZERO)];
        assert!(validate_balanced(&lines).is_err());
    }

    #[test]
    fn zero_total_fails() {
        let lines = vec![(Decimal::ZERO, Decimal::ZERO), (Decimal::ZERO, Decimal::ZERO)];
        assert!(validate_balanced(&lines).is_err());
    }

    #[test]
    fn both_sides_on_one_line_fails() {
        let lines = vec![(dec!(10.00), dec!(10.00)), (Decimal::ZERO, Decimal::ZERO)];
        assert!(validate_balanced(&lines).is_err());
    }

    #[test]
    fn negative_amount_fails() {
        let lines = vec![
            (dec!(-5.00), Decimal::ZERO),
            (Decimal::ZERO, dec!(-5.00)),
        ];
        assert!(validate_balanced(&lines).is_err());
    }

    #[test]
    fn multi_line_split_balances() {
        let lines = vec![
            (dec!(100.00), Decimal::ZERO),
            (Decimal::ZERO, dec!(60.00)),
            (Decimal::ZERO, dec!(40.00)),
        ];
        assert_eq!(validate_balanced(&lines).unwrap(), dec!(100.00));
    }

    #[test]
    fn rounding_beyond_storage_precision_balances() {
        // 3-dp inputs that agree at the 2-dp storage precision must post.
        let lines = vec![(dec!(10.004), Decimal::ZERO), (Decimal::ZERO, dec!(10.001))];
        assert!(validate_balanced(&lines).is_ok());
    }
}
