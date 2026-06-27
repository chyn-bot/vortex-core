//! Units of measure: a category-scoped conversion graph.
//!
//! Every [`Uom`] belongs to exactly one [`UomCategory`]. Within a
//! category there is one **reference** unit whose `factor = 1.0`;
//! every other unit in the category declares its factor as the
//! multiplier from itself to the reference:
//!
//! ```text
//! qty_in_reference_units = qty_in_this_uom * this_uom.factor
//! ```
//!
//! So if the Weight category's reference is `kg`, then:
//! - `g`  has `factor = 0.001`  (1 g = 0.001 kg)
//! - `t`  has `factor = 1000`   (1 t = 1000 kg)
//! - `lb` has `factor ≈ 0.4536` (1 lb = 0.4536 kg)
//!
//! Conversion between two UoMs in the same category goes through
//! the reference:
//!
//! ```text
//! qty_in_target = qty_in_source * source.factor / target.factor
//! ```
//!
//! This is deliberately symmetric and order-independent — no graph
//! walk needed, no dependency on which UoM is the "reference" at
//! call time. The caller just passes two `Uom` values and gets back
//! the converted quantity.
//!
//! Cross-category conversion (kg → m) is a user error, not a
//! "convert through some master scale" operation. [`convert_uom`]
//! returns an error rather than producing a garbage value.

use rust_decimal::Decimal;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use vortex_common::{VortexError, VortexResult};

/// A category of measurement — Weight, Length, Volume, Time, Area,
/// Unit. Conversion is only valid within a category.
#[derive(Debug, Clone)]
pub struct UomCategory {
    pub id: Uuid,
    pub name: String,
    pub active: bool,
}

impl UomCategory {
    fn from_row(row: &sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            active: row.get("active"),
        }
    }

    pub async fn find_by_name(pool: &PgPool, name: &str) -> VortexResult<Option<Self>> {
        let row = sqlx::query("SELECT id, name, active FROM uom_categories WHERE name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        Ok(row.as_ref().map(UomCategory::from_row))
    }
}

/// Type tag describing where a unit sits relative to its category's
/// reference unit. Stored as a string in the DB for forward
/// compatibility — the commerce module treats unknown values as
/// `Reference` for safety, but new variants can be added without
/// breaking old deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UomType {
    /// The category's reference unit. Exactly one per category; its
    /// `factor` is `1.0`.
    Reference,
    /// A multiple of the reference (e.g. tonne when reference is kg).
    Bigger,
    /// A fraction of the reference (e.g. gram when reference is kg).
    Smaller,
}

impl UomType {
    pub fn as_str(&self) -> &'static str {
        match self {
            UomType::Reference => "reference",
            UomType::Bigger => "bigger",
            UomType::Smaller => "smaller",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "bigger" => UomType::Bigger,
            "smaller" => UomType::Smaller,
            _ => UomType::Reference,
        }
    }
}

/// A unit of measure.
#[derive(Debug, Clone)]
pub struct Uom {
    pub id: Uuid,
    pub category_id: Uuid,
    /// Human-readable name, e.g. `"Kilogram"`.
    pub name: String,
    /// Short code used in forms and lookups, e.g. `"kg"`.
    pub code: String,
    /// Multiplier from this unit to the category's reference unit.
    /// `1 this_uom = factor reference_uom`.
    pub factor: Decimal,
    pub uom_type: UomType,
    /// Smallest representable unit, for quantity rounding.
    pub rounding: Decimal,
    pub active: bool,
}

impl Uom {
    fn from_row(row: &sqlx::postgres::PgRow) -> Self {
        let uom_type_str: String = row.get("uom_type");
        Self {
            id: row.get("id"),
            category_id: row.get("category_id"),
            name: row.get("name"),
            code: row.get("code"),
            factor: row.get("factor"),
            uom_type: UomType::from_str(&uom_type_str),
            rounding: row.get("rounding"),
            active: row.get("active"),
        }
    }

    pub async fn find_by_code(pool: &PgPool, code: &str) -> VortexResult<Option<Self>> {
        let row = sqlx::query(
            "SELECT id, category_id, name, code, factor, uom_type, rounding, active \
             FROM uoms WHERE code = $1",
        )
        .bind(code)
        .fetch_optional(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        Ok(row.as_ref().map(Uom::from_row))
    }

    /// List every unit in a given category, ordered by factor so the
    /// caller sees smallest → reference → biggest. Useful for UI
    /// selectors and reports.
    pub async fn list_for_category(
        pool: &PgPool,
        category_id: Uuid,
    ) -> VortexResult<Vec<Self>> {
        let rows = sqlx::query(
            "SELECT id, category_id, name, code, factor, uom_type, rounding, active \
             FROM uoms WHERE category_id = $1 AND active ORDER BY factor",
        )
        .bind(category_id)
        .fetch_all(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        Ok(rows.iter().map(Uom::from_row).collect())
    }
}

/// Convert `qty` from `source` to `target`. Both UoMs must belong to
/// the same category; cross-category conversion is an error.
///
/// Pure function, no DB. Unit-testable directly.
///
/// ```text
/// qty_in_target = qty_in_source * source.factor / target.factor
/// ```
pub fn convert_uom(qty: Decimal, source: &Uom, target: &Uom) -> VortexResult<Decimal> {
    if source.category_id != target.category_id {
        return Err(VortexError::ValidationFailed(format!(
            "cannot convert across UoM categories: '{}' and '{}' are not comparable",
            source.code, target.code
        )));
    }
    if target.factor.is_zero() {
        return Err(VortexError::ValidationFailed(format!(
            "target UoM '{}' has zero factor — misconfigured catalog",
            target.code
        )));
    }

    // Same-uom shortcut avoids unnecessary arithmetic.
    if source.code == target.code {
        return Ok(qty);
    }

    qty.checked_mul(source.factor)
        .and_then(|v| v.checked_div(target.factor))
        .ok_or_else(|| {
            VortexError::ValidationFailed("UoM conversion overflow".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn weight_cat() -> Uuid {
        Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0002)
    }

    fn length_cat() -> Uuid {
        Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0003)
    }

    fn kg() -> Uom {
        Uom {
            id: Uuid::nil(),
            category_id: weight_cat(),
            name: "Kilogram".into(),
            code: "kg".into(),
            factor: dec!(1),
            uom_type: UomType::Reference,
            rounding: dec!(0.001),
            active: true,
        }
    }

    fn g() -> Uom {
        Uom {
            id: Uuid::nil(),
            category_id: weight_cat(),
            name: "Gram".into(),
            code: "g".into(),
            factor: dec!(0.001),
            uom_type: UomType::Smaller,
            rounding: dec!(0.01),
            active: true,
        }
    }

    fn tonne() -> Uom {
        Uom {
            id: Uuid::nil(),
            category_id: weight_cat(),
            name: "Tonne".into(),
            code: "t".into(),
            factor: dec!(1000),
            uom_type: UomType::Bigger,
            rounding: dec!(0.001),
            active: true,
        }
    }

    fn meter() -> Uom {
        Uom {
            id: Uuid::nil(),
            category_id: length_cat(),
            name: "Meter".into(),
            code: "m".into(),
            factor: dec!(1),
            uom_type: UomType::Reference,
            rounding: dec!(0.001),
            active: true,
        }
    }

    #[test]
    fn kg_to_g_is_multiplication_by_thousand() {
        assert_eq!(convert_uom(dec!(5), &kg(), &g()).unwrap(), dec!(5000));
        assert_eq!(convert_uom(dec!(0.5), &kg(), &g()).unwrap(), dec!(500));
    }

    #[test]
    fn g_to_kg_is_division_by_thousand() {
        assert_eq!(convert_uom(dec!(5000), &g(), &kg()).unwrap(), dec!(5));
        assert_eq!(convert_uom(dec!(250), &g(), &kg()).unwrap(), dec!(0.25));
    }

    #[test]
    fn tonne_to_g_round_trips() {
        let half_tonne = dec!(0.5);
        let in_g = convert_uom(half_tonne, &tonne(), &g()).unwrap();
        assert_eq!(in_g, dec!(500000));
        let back = convert_uom(in_g, &g(), &tonne()).unwrap();
        assert_eq!(back, half_tonne);
    }

    #[test]
    fn same_uom_is_identity() {
        assert_eq!(convert_uom(dec!(42.5), &kg(), &kg()).unwrap(), dec!(42.5));
    }

    #[test]
    fn cross_category_conversion_errors() {
        let result = convert_uom(dec!(5), &kg(), &meter());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("cannot convert across UoM categories"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn zero_factor_target_errors() {
        let mut broken = kg();
        broken.factor = dec!(0);
        let result = convert_uom(dec!(5), &kg(), &broken);
        assert!(result.is_err());
    }

    #[test]
    fn uom_type_roundtrip() {
        assert_eq!(UomType::from_str("reference"), UomType::Reference);
        assert_eq!(UomType::from_str("bigger"), UomType::Bigger);
        assert_eq!(UomType::from_str("smaller"), UomType::Smaller);
        // Unknown variants default to Reference (forward-compat).
        assert_eq!(UomType::from_str("weird_future_variant"), UomType::Reference);
    }
}
