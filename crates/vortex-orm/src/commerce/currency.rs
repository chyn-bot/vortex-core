//! Currency, exchange rates, and currency-scoped rounding.
//!
//! ## Model
//!
//! - [`Currency`] is a row in the `currencies` table — ISO 4217 code,
//!   display metadata, and a `rounding` field that determines the
//!   smallest representable unit (0.01 for most, 1 for JPY / IDR,
//!   0.05 for CHF-style nickel rounding if anyone wires it up).
//! - [`CurrencyRate`] is a `(currency_id, rate_date, rate)` triple
//!   stored in `currency_rates`. Rates are expressed **relative to
//!   a platform base currency**; the base is whichever currency
//!   fresh seeds pin to `1.0` (USD today, easily changed per-tenant
//!   by loading custom rates). The conversion math normalizes
//!   through the base, so `convert(X, A, B, date)` works even when
//!   neither A nor B is the base.
//!
//! ## Conversion math
//!
//! Given a rate row saying "on date D, `rate` is how many units of
//! currency C equal one unit of base":
//!
//! ```text
//! amount_in_base = amount_in_C / rate_C
//! amount_in_B    = amount_in_base * rate_B
//!                = amount_in_C * (rate_B / rate_C)
//! ```
//!
//! Rounding to the target currency's `rounding` unit happens *after*
//! the arithmetic, never during — intermediate steps use the full
//! [`Decimal`] precision to avoid compounding rounding errors across
//! chained operations.
//!
//! If a currency has no rate row for a given date, the lookup walks
//! backwards to the most recent rate on or before the date. A
//! currency with no rate rows at all returns `None`; the seed
//! migration inserts `rate = 1.0` for every currency on the
//! migration date so the out-of-the-box experience is "all amounts
//! convert at 1:1 until you load real rates".

use chrono::NaiveDate;
use rust_decimal::Decimal;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use vortex_common::{VortexError, VortexResult};

/// A currency definition. One row per ISO 4217 code (plus whatever
/// custom codes a deployment inserts). Every amount stored on a
/// domain table carries a `currency_id` pointing to this table.
#[derive(Debug, Clone)]
pub struct Currency {
    pub id: Uuid,
    /// ISO 4217 three-letter code, e.g. `"MYR"`, `"USD"`.
    pub code: String,
    /// Human-readable name, e.g. `"Malaysian Ringgit"`.
    pub name: String,
    /// Display symbol, e.g. `"RM"`, `"$"`, `"€"`.
    pub symbol: String,
    /// Where to render the symbol relative to the numeric value:
    /// `"before"` (most currencies) or `"after"` (some European
    /// conventions).
    pub symbol_position: String,
    /// Number of decimal places shown in default formatting.
    /// 2 for most, 0 for JPY/IDR, 3 for some Middle Eastern currencies.
    pub decimal_places: i16,
    /// Smallest representable unit. All conversion results are
    /// snapped to a multiple of this value.
    pub rounding: Decimal,
    pub active: bool,
}

impl Currency {
    fn from_row(row: &sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            code: row.get("code"),
            name: row.get("name"),
            symbol: row.get("symbol"),
            symbol_position: row.get("symbol_position"),
            decimal_places: row.get("decimal_places"),
            rounding: row.get("rounding"),
            active: row.get("active"),
        }
    }

    /// Look up a currency by its ISO code. Returns `None` if the code
    /// is not present in the `currencies` table (typo, custom code
    /// not seeded, etc.).
    pub async fn find_by_code(pool: &PgPool, code: &str) -> VortexResult<Option<Self>> {
        let row = sqlx::query(
            "SELECT id, code, name, symbol, symbol_position, decimal_places, rounding, active \
             FROM currencies WHERE code = $1",
        )
        .bind(code)
        .fetch_optional(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(row.as_ref().map(Currency::from_row))
    }

    /// List every active currency in stable order (by code).
    /// Typical caller is a UI dropdown or a seed step.
    pub async fn list_active(pool: &PgPool) -> VortexResult<Vec<Self>> {
        let rows = sqlx::query(
            "SELECT id, code, name, symbol, symbol_position, decimal_places, rounding, active \
             FROM currencies WHERE active ORDER BY code",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(rows.iter().map(Currency::from_row).collect())
    }
}

/// An exchange rate for a currency on a specific date.
/// Persisted in `currency_rates`; multiple rows per currency form a
/// time-series that [`get_rate`] walks backwards from a target date.
#[derive(Debug, Clone)]
pub struct CurrencyRate {
    pub id: Uuid,
    pub currency_id: Uuid,
    /// Rate relative to the platform base currency: one unit of
    /// *this* currency equals `rate` units of the base.
    pub rate: Decimal,
    pub rate_date: NaiveDate,
}

/// Fetch the most recent rate for a currency on or before `date`.
///
/// Returns `None` if:
///   - the currency code does not exist, **or**
///   - no rate row exists on or before `date` (e.g. querying a date
///     before any rates were loaded).
///
/// Callers that treat "no rate" as an error should `.ok_or_else(...)`
/// to produce their own domain error. [`convert_amount`] does exactly
/// that.
pub async fn get_rate(
    pool: &PgPool,
    currency_code: &str,
    date: NaiveDate,
) -> VortexResult<Option<Decimal>> {
    let rate: Option<Decimal> = sqlx::query_scalar(
        "SELECT r.rate \
         FROM currency_rates r \
         JOIN currencies c ON c.id = r.currency_id \
         WHERE c.code = $1 AND r.rate_date <= $2 \
         ORDER BY r.rate_date DESC \
         LIMIT 1",
    )
    .bind(currency_code)
    .bind(date)
    .fetch_optional(pool)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(rate)
}

/// Convert `amount` from `from_code` to `to_code` using the rates
/// effective on `date`. Result is rounded to the target currency's
/// `rounding` unit.
///
/// Errors if:
///   - either currency code is unknown to the `currencies` table, or
///   - either currency has no rate row on or before `date`.
///
/// Same-currency conversion is a no-op and does not hit the database
/// for a rate lookup — the common "convert MYR to MYR" case costs
/// zero queries.
pub async fn convert_amount(
    pool: &PgPool,
    amount: Decimal,
    from_code: &str,
    to_code: &str,
    date: NaiveDate,
) -> VortexResult<Decimal> {
    if from_code == to_code {
        // No currency lookup needed — but we still want to round to
        // the currency's unit for consistency with the cross-currency
        // path. One query instead of three.
        let to = Currency::find_by_code(pool, to_code)
            .await?
            .ok_or_else(|| {
                VortexError::ValidationFailed(format!("unknown currency code: {to_code}"))
            })?;
        return Ok(round_to_currency(amount, &to));
    }

    let from_rate = get_rate(pool, from_code, date).await?.ok_or_else(|| {
        VortexError::ValidationFailed(format!(
            "no exchange rate for {from_code} on or before {date}"
        ))
    })?;
    let to_rate = get_rate(pool, to_code, date).await?.ok_or_else(|| {
        VortexError::ValidationFailed(format!(
            "no exchange rate for {to_code} on or before {date}"
        ))
    })?;

    // We need the `to` currency for rounding.
    let to = Currency::find_by_code(pool, to_code).await?.ok_or_else(|| {
        VortexError::ValidationFailed(format!("unknown currency code: {to_code}"))
    })?;

    // amount_in_base = amount / from_rate
    // amount_in_to   = amount_in_base * to_rate
    //                = amount * to_rate / from_rate
    //
    // Multiplication before division avoids losing precision on
    // small amounts. rust_decimal's default precision is more than
    // enough for everyday currency work; we're not doing HFT here.
    let converted = amount
        .checked_mul(to_rate)
        .and_then(|v| v.checked_div(from_rate))
        .ok_or_else(|| {
            VortexError::ValidationFailed("currency conversion overflow".to_string())
        })?;

    Ok(round_to_currency(converted, &to))
}

/// Snap an amount to a multiple of the currency's `rounding` unit,
/// using banker's rounding semantics (ties to even) — matches the
/// financial convention expected by auditors.
///
/// Pure function, no DB. Unit-testable directly.
pub fn round_to_currency(amount: Decimal, currency: &Currency) -> Decimal {
    if currency.rounding.is_zero() {
        // Degenerate config — treat as "no rounding".
        return amount;
    }
    // (amount / rounding).round() * rounding
    //
    // Using `round_dp_with_strategy(0, MidpointNearestEven)` on the
    // quotient gives banker's rounding. Multiplying back produces a
    // value that is always an exact multiple of `rounding`.
    use rust_decimal::RoundingStrategy;
    let quotient = amount / currency.rounding;
    let rounded_quotient = quotient.round_dp_with_strategy(0, RoundingStrategy::MidpointNearestEven);
    rounded_quotient * currency.rounding
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn myr() -> Currency {
        Currency {
            id: Uuid::nil(),
            code: "MYR".to_string(),
            name: "Malaysian Ringgit".to_string(),
            symbol: "RM".to_string(),
            symbol_position: "before".to_string(),
            decimal_places: 2,
            rounding: dec!(0.01),
            active: true,
        }
    }

    fn jpy() -> Currency {
        Currency {
            id: Uuid::nil(),
            code: "JPY".to_string(),
            name: "Japanese Yen".to_string(),
            symbol: "¥".to_string(),
            symbol_position: "before".to_string(),
            decimal_places: 0,
            rounding: dec!(1),
            active: true,
        }
    }

    fn nickel_chf() -> Currency {
        // Swiss-style 5-cent rounding: `rounding = 0.05`
        Currency {
            id: Uuid::nil(),
            code: "CHF".to_string(),
            name: "Swiss Franc".to_string(),
            symbol: "CHF".to_string(),
            symbol_position: "before".to_string(),
            decimal_places: 2,
            rounding: dec!(0.05),
            active: true,
        }
    }

    #[test]
    fn round_myr_to_two_decimals() {
        // 10.125 → 10.12 (banker's rounding: ties to even)
        assert_eq!(round_to_currency(dec!(10.125), &myr()), dec!(10.12));
        // 10.135 → 10.14
        assert_eq!(round_to_currency(dec!(10.135), &myr()), dec!(10.14));
        // Exact value passes through unchanged.
        assert_eq!(round_to_currency(dec!(10.00), &myr()), dec!(10.00));
        // Typical ragged amount gets cleaned up.
        assert_eq!(round_to_currency(dec!(10.999), &myr()), dec!(11.00));
    }

    #[test]
    fn round_jpy_has_no_fractional_yen() {
        assert_eq!(round_to_currency(dec!(1234.56), &jpy()), dec!(1235));
        assert_eq!(round_to_currency(dec!(1234.49), &jpy()), dec!(1234));
        assert_eq!(round_to_currency(dec!(1234), &jpy()), dec!(1234));
    }

    #[test]
    fn round_nickel_chf_snaps_to_five_cents() {
        assert_eq!(round_to_currency(dec!(10.02), &nickel_chf()), dec!(10.00));
        assert_eq!(round_to_currency(dec!(10.03), &nickel_chf()), dec!(10.05));
        assert_eq!(round_to_currency(dec!(10.07), &nickel_chf()), dec!(10.05));
        assert_eq!(round_to_currency(dec!(10.08), &nickel_chf()), dec!(10.10));
    }

    #[test]
    fn zero_rounding_is_passthrough() {
        let mut c = myr();
        c.rounding = dec!(0);
        assert_eq!(round_to_currency(dec!(10.1234567), &c), dec!(10.1234567));
    }
}
