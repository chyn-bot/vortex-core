//! Malaysian tax engine — per-tax aggregation, GL account resolution,
//! and the SST-02 return query.
//!
//! Design: commerce `taxes` stays generic (rate + kind); everything
//! Malaysia-specific lives in `acc_tax_config` (GL account, SST-02
//! category, MyInvois tax type code). Posting writes one GL tax line
//! **per distinct tax** carrying `tax_id` + `tax_base_amount`, so the
//! SST-02 return and the MyInvois tax blocks read straight off the
//! ledger and cannot drift from each other.

use std::collections::BTreeMap;

use vortex_plugin_sdk::chrono::NaiveDate;
use vortex_plugin_sdk::common::{VortexError, VortexResult};
use vortex_plugin_sdk::orm::commerce::{compute_tax_amount, Tax};
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

/// One tax's aggregate over a document: taxable base and tax amount.
/// Amounts are rounded to 2 dp PER LINE before summing — matching the
/// header totals in `compute_document_totals` (so the move always
/// balances) and LHDN's line-level validation, where each e-invoice
/// line carries its own rounded tax and subtotals must equal their sum.
#[derive(Debug, Clone, PartialEq)]
pub struct TaxBucket {
    pub tax_id: Uuid,
    pub tax_name: String,
    pub base: Decimal,
    pub tax: Decimal,
}

/// Aggregate document lines by tax. Input: `(gross_line_amount,
/// Option<&Tax>)` per commercial line, where gross is quantity ×
/// unit price (2 dp). Lines without tax contribute nothing here (their
/// base is not taxable value). Pure — unit-tested without a database.
pub fn aggregate_by_tax(lines: &[(Decimal, Option<&Tax>)]) -> Vec<TaxBucket> {
    let mut buckets: BTreeMap<Uuid, TaxBucket> = BTreeMap::new();
    for (gross, tax) in lines {
        let Some(tax) = tax else { continue };
        let computed = compute_tax_amount(*gross, tax);
        let entry = buckets.entry(tax.id).or_insert_with(|| TaxBucket {
            tax_id: tax.id,
            tax_name: tax.name.clone(),
            base: Decimal::ZERO,
            tax: Decimal::ZERO,
        });
        entry.base += computed.base.round_dp(2);
        entry.tax += computed.tax.round_dp(2);
    }
    let mut out: Vec<TaxBucket> = buckets.into_values().collect();
    // Stable output order for deterministic GL line sequences.
    out.sort_by(|a, b| a.tax_name.cmp(&b.tax_name));
    out
}

/// GL account a tax posts to: per-tax config (company row wins over the
/// shared NULL-company row), falling back to the company default tax
/// account in `acc_config`.
pub async fn tax_account_for(
    db: &PgPool,
    company_id: Option<Uuid>,
    tax_id: Uuid,
) -> VortexResult<Option<Uuid>> {
    let configured: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT tax_account_id FROM acc_tax_config \
         WHERE tax_id = $1 AND (company_id = $2 OR company_id IS NULL) \
           AND tax_account_id IS NOT NULL \
         ORDER BY company_id NULLS LAST LIMIT 1",
    )
    .bind(tax_id)
    .bind(company_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    if configured.is_some() {
        return Ok(configured);
    }
    crate::service::default_account(db, company_id, "tax").await
}

/// One row of the SST-02 worksheet: an SST category's taxable value and
/// tax amount over a period, split output (sales) vs input (purchases).
#[derive(Debug, Clone)]
pub struct SstReturnRow {
    pub sst_category: String,
    pub direction: String, // "output" | "input"
    pub taxable_value: Decimal,
    pub tax_amount: Decimal,
}

/// Aggregate posted tax lines for the SST-02 return. Reads the GL
/// (`tax_base_amount` + amounts on tax lines), classified by
/// `acc_tax_config.sst_category`; direction from the tax's
/// `type_tax_use`. Only posted, non-reversed-state periods count —
/// reversals net out naturally because they post opposite signs.
pub async fn sst_return(
    db: &PgPool,
    company_id: Option<Uuid>,
    from: NaiveDate,
    to: NaiveDate,
) -> VortexResult<Vec<SstReturnRow>> {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT c.sst_category, \
                CASE WHEN t.type_tax_use = 'purchase' THEN 'input' ELSE 'output' END AS direction, \
                COALESCE(SUM(l.tax_base_amount), 0) AS taxable_value, \
                SUM(CASE WHEN l.credit > 0 THEN l.credit ELSE -l.debit END \
                    * CASE WHEN t.type_tax_use = 'purchase' THEN -1 ELSE 1 END) AS tax_amount \
         FROM acc_move_line l \
         JOIN acc_move m ON m.id = l.move_id \
         JOIN taxes t ON t.id = l.tax_id \
         LEFT JOIN acc_tax_config c0 ON c0.tax_id = t.id \
              AND (c0.company_id = $1 OR c0.company_id IS NULL) \
         CROSS JOIN LATERAL (SELECT COALESCE(c0.sst_category, 'out_of_scope') AS sst_category) c \
         WHERE m.state = 'posted' AND l.tax_id IS NOT NULL \
           AND m.move_date BETWEEN $2 AND $3 \
           AND (m.company_id = $1 OR ($1 IS NULL AND m.company_id IS NULL)) \
         GROUP BY c.sst_category, direction \
         ORDER BY direction DESC, c.sst_category",
    )
    .bind(company_id)
    .bind(from)
    .bind(to)
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(rows
        .iter()
        .map(|r| SstReturnRow {
            sst_category: r.get("sst_category"),
            direction: r.get("direction"),
            taxable_value: r.get("taxable_value"),
            tax_amount: r.get("tax_amount"),
        })
        .collect())
}

/// Overlap guard for fiscal-year creation (no btree_gist dependency —
/// enforced here, called by the fiscal-year handlers).
pub async fn fiscal_year_overlapping(
    db: &PgPool,
    company_id: Option<Uuid>,
    date_from: NaiveDate,
    date_to: NaiveDate,
    exclude_id: Option<Uuid>,
) -> VortexResult<bool> {
    let count: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM acc_fiscal_year \
         WHERE (company_id = $1 OR (company_id IS NULL AND $1 IS NULL)) \
           AND daterange(date_from, date_to, '[]') && daterange($2, $3, '[]') \
           AND ($4::uuid IS NULL OR id <> $4)",
    )
    .bind(company_id)
    .bind(date_from)
    .bind(date_to)
    .bind(exclude_id)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use vortex_plugin_sdk::orm::commerce::{TaxAmountType, TaxTypeUse};

    fn tax(id_byte: u8, name: &str, rate: Decimal, inclusive: bool) -> Tax {
        Tax {
            id: Uuid::from_bytes([id_byte; 16]),
            name: name.into(),
            description: None,
            amount_type: TaxAmountType::Percent,
            amount: rate,
            type_tax_use: TaxTypeUse::Sale,
            price_include: inclusive,
            active: true,
        }
    }

    #[test]
    fn aggregates_per_tax_across_lines() {
        let st8 = tax(1, "Service Tax 8%", dec!(8), false);
        let st6 = tax(2, "Service Tax 6%", dec!(6), false);
        let lines = vec![
            (dec!(1000.00), Some(&st8)),
            (dec!(500.00), Some(&st8)),
            (dec!(200.00), Some(&st6)),
            (dec!(999.99), None), // untaxed line contributes nothing
        ];
        let buckets = aggregate_by_tax(&lines);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].tax_name, "Service Tax 6%");
        assert_eq!(buckets[0].base, dec!(200.00));
        assert_eq!(buckets[0].tax, dec!(12.00));
        assert_eq!(buckets[1].tax_name, "Service Tax 8%");
        assert_eq!(buckets[1].base, dec!(1500.00));
        assert_eq!(buckets[1].tax, dec!(120.00));
    }

    #[test]
    fn inclusive_prices_back_out_the_base() {
        let st8 = tax(1, "Service Tax 8% incl", dec!(8), true);
        let buckets = aggregate_by_tax(&[(dec!(108.00), Some(&st8))]);
        assert_eq!(buckets[0].base, dec!(100.00));
        assert_eq!(buckets[0].tax, dec!(8.00));
    }

    #[test]
    fn rounding_is_per_line_matching_header_totals() {
        // Three lines of 33.33 at 8%: per-line tax 2.6664 → rounded
        // 2.67 each → 8.01. This MUST match compute_document_totals'
        // per-line rounding or the posted move would not balance.
        let st8 = tax(1, "Service Tax 8%", dec!(8), false);
        let lines = vec![
            (dec!(33.33), Some(&st8)),
            (dec!(33.33), Some(&st8)),
            (dec!(33.33), Some(&st8)),
        ];
        let buckets = aggregate_by_tax(&lines);
        assert_eq!(buckets[0].base, dec!(99.99));
        assert_eq!(buckets[0].tax, dec!(8.01));
    }

    #[test]
    fn empty_and_untaxed_only_inputs() {
        assert!(aggregate_by_tax(&[]).is_empty());
        assert!(aggregate_by_tax(&[(dec!(50), None)]).is_empty());
    }
}
