//! Minimal tax model — percent / fixed, sale / purchase, inclusive
//! / exclusive. Enough for Malaysian SST and GST-style VATs without
//! the weight of Odoo's full `account.tax` machinery.
//!
//! ## Model
//!
//! - **`amount_type`**: `percent` (amount is a percentage, e.g. `6`
//!   for 6%) or `fixed` (amount is a per-line-item fee in the
//!   tax's currency).
//! - **`type_tax_use`**: `sale`, `purchase`, or `none`. Lets the
//!   commerce plugin filter the catalog by context without ambiguity.
//! - **`price_include`**: whether the tax is already rolled into the
//!   displayed "unit price". When `true`, computing the tax amount
//!   means backing it out of the base; when `false`, the tax is
//!   added on top of the base.
//!
//! ## Not modelled (deferred)
//!
//! - Compound taxes (tax on tax)
//! - Tax groups / sequenced application
//! - Tax reports and returns
//! - Per-company tax accounts / ledger mapping
//!
//! These belong in a Finance plugin that consumes this primitive,
//! not in the platform primitive itself. The moment this module
//! grows a `tax_parent_id` column or a `sequence` field is the
//! moment it stops being a primitive and starts being an accounting
//! module.

use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use vortex_common::{VortexError, VortexResult};

/// What kind of `amount` a tax carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaxAmountType {
    /// Amount is a percentage — 6.0 means 6%.
    Percent,
    /// Amount is a fixed fee in currency units, applied once per
    /// taxable line.
    Fixed,
}

impl TaxAmountType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaxAmountType::Percent => "percent",
            TaxAmountType::Fixed => "fixed",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "fixed" => TaxAmountType::Fixed,
            _ => TaxAmountType::Percent,
        }
    }
}

/// Which commerce direction a tax applies to. Used by the commerce
/// plugin to populate sale vs purchase tax pickers without mixing
/// them up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaxTypeUse {
    Sale,
    Purchase,
    /// Informational only — does not auto-apply in either direction.
    None,
}

impl TaxTypeUse {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaxTypeUse::Sale => "sale",
            TaxTypeUse::Purchase => "purchase",
            TaxTypeUse::None => "none",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "sale" => TaxTypeUse::Sale,
            "purchase" => TaxTypeUse::Purchase,
            _ => TaxTypeUse::None,
        }
    }
}

/// A tax definition.
#[derive(Debug, Clone)]
pub struct Tax {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub amount_type: TaxAmountType,
    /// For `Percent`, this is 6.0 for 6%. For `Fixed`, it's the flat
    /// amount in whatever currency the consumer is using.
    pub amount: Decimal,
    pub type_tax_use: TaxTypeUse,
    /// If `true`, the tax is already included in the line's unit
    /// price and must be backed out of the base. If `false`, the
    /// tax is added to the base to produce the total.
    pub price_include: bool,
    pub active: bool,
}

impl Tax {
    fn from_row(row: &sqlx::postgres::PgRow) -> Self {
        let amount_type_str: String = row.get("amount_type");
        let type_tax_use_str: String = row.get("type_tax_use");
        Self {
            id: row.get("id"),
            name: row.get("name"),
            description: row.try_get("description").ok(),
            amount_type: TaxAmountType::from_str(&amount_type_str),
            amount: row.get("amount"),
            type_tax_use: TaxTypeUse::from_str(&type_tax_use_str),
            price_include: row.get("price_include"),
            active: row.get("active"),
        }
    }

    pub async fn find_by_name(pool: &PgPool, name: &str) -> VortexResult<Option<Self>> {
        let row = sqlx::query(
            "SELECT id, name, description, amount_type, amount, type_tax_use, \
             price_include, active FROM taxes WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        Ok(row.as_ref().map(Tax::from_row))
    }

    /// List every active tax filtered by direction. Pass
    /// [`TaxTypeUse::Sale`] for "show me all sale taxes", etc.
    pub async fn list_active_by_use(
        pool: &PgPool,
        use_kind: TaxTypeUse,
    ) -> VortexResult<Vec<Self>> {
        let rows = sqlx::query(
            "SELECT id, name, description, amount_type, amount, type_tax_use, \
             price_include, active FROM taxes \
             WHERE active AND type_tax_use = $1 ORDER BY name",
        )
        .bind(use_kind.as_str())
        .fetch_all(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        Ok(rows.iter().map(Tax::from_row).collect())
    }
}

/// The outcome of applying a tax to a base amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxComputation {
    /// The net amount *before* the tax (the "base" the tax rate
    /// applies to). For an exclusive tax this is the same as the
    /// input; for an inclusive tax this is backed out of the input.
    pub base: Decimal,
    /// The tax amount itself.
    pub tax: Decimal,
    /// `base + tax` — provided for convenience so callers don't
    /// have to recompute.
    pub total: Decimal,
}

/// Compute how a tax applies to an amount. The shape of the
/// computation depends on `price_include`:
///
/// - **`price_include = false`** (exclusive): the input `amount` is
///   the base. The tax is `amount * rate` (or the fixed `amount`
///   for fixed taxes), added on top. `total = base + tax`.
/// - **`price_include = true`** (inclusive): the input `amount` is
///   the total (tax-inclusive price). The base is backed out as
///   `amount / (1 + rate)` for percent taxes, or `amount - fixed`
///   for fixed taxes. `tax = amount - base`.
///
/// Pure function — no DB. Unit-testable directly.
pub fn compute_tax_amount(amount: Decimal, tax: &Tax) -> TaxComputation {
    match (tax.amount_type, tax.price_include) {
        (TaxAmountType::Percent, false) => {
            // base is the input, tax adds on top
            let rate = tax.amount / dec!(100);
            let tax_amt = amount * rate;
            TaxComputation {
                base: amount,
                tax: tax_amt,
                total: amount + tax_amt,
            }
        }
        (TaxAmountType::Percent, true) => {
            // amount already includes tax; back out the base
            // base = amount / (1 + rate)
            let one = dec!(1);
            let rate = tax.amount / dec!(100);
            let base = amount / (one + rate);
            let tax_amt = amount - base;
            TaxComputation {
                base,
                tax: tax_amt,
                total: amount,
            }
        }
        (TaxAmountType::Fixed, false) => TaxComputation {
            base: amount,
            tax: tax.amount,
            total: amount + tax.amount,
        },
        (TaxAmountType::Fixed, true) => {
            // Fixed inclusive — rare but semantically "the displayed
            // price is the total, the fixed fee is embedded". Back
            // out the base by subtraction.
            let base = amount - tax.amount;
            TaxComputation {
                base,
                tax: tax.amount,
                total: amount,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn sst_6() -> Tax {
        Tax {
            id: Uuid::nil(),
            name: "SST 6%".to_string(),
            description: None,
            amount_type: TaxAmountType::Percent,
            amount: dec!(6),
            type_tax_use: TaxTypeUse::Sale,
            price_include: false,
            active: true,
        }
    }

    fn sst_6_inclusive() -> Tax {
        let mut t = sst_6();
        t.price_include = true;
        t
    }

    fn handling_fee() -> Tax {
        Tax {
            id: Uuid::nil(),
            name: "Handling".to_string(),
            description: None,
            amount_type: TaxAmountType::Fixed,
            amount: dec!(5),
            type_tax_use: TaxTypeUse::Sale,
            price_include: false,
            active: true,
        }
    }

    #[test]
    fn percent_exclusive_adds_on_top() {
        let c = compute_tax_amount(dec!(100), &sst_6());
        assert_eq!(c.base, dec!(100));
        assert_eq!(c.tax, dec!(6));
        assert_eq!(c.total, dec!(106));
    }

    #[test]
    fn percent_inclusive_backs_out_of_total() {
        // 106 inclusive of 6% SST → base 100, tax 6
        let c = compute_tax_amount(dec!(106), &sst_6_inclusive());
        assert_eq!(c.base, dec!(100));
        assert_eq!(c.tax, dec!(6));
        assert_eq!(c.total, dec!(106));
    }

    #[test]
    fn percent_inclusive_round_trip() {
        // Start from base 57.34, add tax exclusively, then treat the
        // result as inclusive and back it out. Should land back on
        // the original base.
        let exclusive = compute_tax_amount(dec!(57.34), &sst_6());
        let inclusive = compute_tax_amount(exclusive.total, &sst_6_inclusive());
        assert_eq!(inclusive.base, dec!(57.34));
    }

    #[test]
    fn fixed_exclusive_adds_flat_fee() {
        let c = compute_tax_amount(dec!(100), &handling_fee());
        assert_eq!(c.base, dec!(100));
        assert_eq!(c.tax, dec!(5));
        assert_eq!(c.total, dec!(105));
    }

    #[test]
    fn fixed_inclusive_backs_out_flat_fee() {
        let mut fee = handling_fee();
        fee.price_include = true;
        let c = compute_tax_amount(dec!(105), &fee);
        assert_eq!(c.base, dec!(100));
        assert_eq!(c.tax, dec!(5));
        assert_eq!(c.total, dec!(105));
    }

    #[test]
    fn zero_percent_tax_is_identity() {
        let mut exempt = sst_6();
        exempt.amount = dec!(0);
        let c = compute_tax_amount(dec!(42.5), &exempt);
        assert_eq!(c.base, dec!(42.5));
        assert_eq!(c.tax, dec!(0));
        assert_eq!(c.total, dec!(42.5));
    }

    #[test]
    fn amount_type_roundtrip() {
        assert_eq!(TaxAmountType::from_str("percent"), TaxAmountType::Percent);
        assert_eq!(TaxAmountType::from_str("fixed"), TaxAmountType::Fixed);
        assert_eq!(TaxAmountType::from_str("unknown"), TaxAmountType::Percent);
    }

    #[test]
    fn type_tax_use_roundtrip() {
        assert_eq!(TaxTypeUse::from_str("sale"), TaxTypeUse::Sale);
        assert_eq!(TaxTypeUse::from_str("purchase"), TaxTypeUse::Purchase);
        assert_eq!(TaxTypeUse::from_str("none"), TaxTypeUse::None);
        assert_eq!(TaxTypeUse::from_str("weird"), TaxTypeUse::None);
    }
}
