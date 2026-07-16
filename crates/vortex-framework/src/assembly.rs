//! Calculator-chain document assembly — compose a total from additive parts.
//!
//! A computed document — a bill, an invoice, a payroll slip, a quote — is a set
//! of line items produced by independent calculators and then aggregated. The
//! trap is writing that aggregation as one growing function that every new
//! charge type has to edit; the fix is a **chain of calculators**, each owning
//! one line type, that a new charge type *extends* rather than *modifies* (the
//! open/closed principle the IWK scope calls for by name).
//!
//! This is **core**: nothing here knows what a tariff or a desludging fee is. A
//! [`LineItem`] carries an open `line_type` string the vertical names; the
//! engine only runs calculators in order and sums the result.
//!
//! # Running subtotal
//!
//! Each calculator sees the context *and the lines produced so far*, so
//! order-dependent charges compose naturally: a penalty as a percent of the
//! running subtotal, a prior-balance line, a rounding line — each is just a
//! calculator added after the ones it depends on.
//!
//! # Composing with the rules engine
//!
//! [`crate::rules::AdjustmentResult`]s drop straight in via
//! [`LineItem::from_adjustment`], so a "run the adjustment rules" calculator is
//! a few lines: evaluate, map each adjustment to a line, return them.
//!
//! # Example
//!
//! ```rust,ignore
//! let chain = CalculatorChain::new()
//!     .add("base", |ctx: &BillCtx, _| vec![LineItem::new("base_tariff", "Base", ctx.base)])
//!     .add("adjustments", |ctx: &BillCtx, _| {
//!         ctx.adjustments.iter().map(LineItem::from_adjustment).collect()
//!     })
//!     .add("penalty", |_ctx, sofar| {
//!         let sub = LineItem::sum(sofar);
//!         vec![LineItem::new("penalty", "Late penalty", sub * dec!(0.02))]
//!     });
//! let doc = chain.assemble(&ctx);
//! let total = doc.total();
//! ```

use std::sync::Arc;

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde_json::{json, Value};

use crate::rules::AdjustmentResult;

/// One line of a composed document. `line_type` is an open string the vertical
/// defines (`base_tariff`, `icpt`, `desludging_fee`, `rebate`, `prior_balance`,
/// `penalty`, …); the engine treats it opaquely.
#[derive(Debug, Clone, PartialEq)]
pub struct LineItem {
    pub line_type: String,
    pub label: String,
    pub amount: Decimal,
    /// Optional quantity for volumetric lines; `None` for flat charges.
    pub quantity: Option<Decimal>,
    /// Optional pointer back to what produced this line (a rule id, a reading id).
    pub source_reference: Option<String>,
    /// Free-form structured detail for rendering/audit.
    pub meta: Value,
}

impl LineItem {
    /// A flat line: a type, a label, and an amount.
    pub fn new(line_type: impl Into<String>, label: impl Into<String>, amount: Decimal) -> Self {
        Self {
            line_type: line_type.into(),
            label: label.into(),
            amount,
            quantity: None,
            source_reference: None,
            meta: json!({}),
        }
    }

    pub fn with_quantity(mut self, qty: Decimal) -> Self {
        self.quantity = Some(qty);
        self
    }
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source_reference = Some(source.into());
        self
    }
    pub fn with_meta(mut self, meta: Value) -> Self {
        self.meta = meta;
        self
    }

    /// Build a line from a rules-engine adjustment, preserving its type, amount,
    /// and provenance (rule id + reason code) so the assembled document stays
    /// traceable to the rule that produced the charge.
    pub fn from_adjustment(adj: &AdjustmentResult) -> Self {
        Self {
            line_type: adj.adjustment_type.clone(),
            label: adj.rule_name.clone(),
            amount: adj.amount,
            quantity: None,
            source_reference: Some(adj.rule_id.to_string()),
            meta: json!({
                "rule_version": adj.rule_version,
                "reason_code": adj.reason_code,
            }),
        }
    }

    /// Sum the amounts of a slice of lines — the running subtotal a calculator
    /// receives.
    pub fn sum(lines: &[LineItem]) -> Decimal {
        lines.iter().map(|l| l.amount).sum()
    }
}

/// A calculator: given the context and the lines accumulated so far, produce
/// zero or more new lines. Registered into a [`CalculatorChain`].
pub type Calculator<C> = Arc<dyn Fn(&C, &[LineItem]) -> Vec<LineItem> + Send + Sync>;

/// An ordered chain of calculators over a context type `C`. Extend it with
/// [`add`](Self::add); a new charge type is a new calculator, never an edit to
/// an existing one.
pub struct CalculatorChain<C> {
    calculators: Vec<(String, Calculator<C>)>,
}

impl<C> Default for CalculatorChain<C> {
    fn default() -> Self {
        Self {
            calculators: Vec::new(),
        }
    }
}

impl<C> CalculatorChain<C> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a calculator. `name` labels it for diagnostics. Returns `self` for
    /// fluent construction.
    pub fn add<F>(mut self, name: impl Into<String>, f: F) -> Self
    where
        F: Fn(&C, &[LineItem]) -> Vec<LineItem> + Send + Sync + 'static,
    {
        self.calculators.push((name.into(), Arc::new(f)));
        self
    }

    /// Number of calculators in the chain.
    pub fn len(&self) -> usize {
        self.calculators.len()
    }
    pub fn is_empty(&self) -> bool {
        self.calculators.is_empty()
    }

    /// Run every calculator in order against `ctx`, threading the accumulated
    /// lines through each, and return the assembled document. Deterministic:
    /// same context + same chain ⇒ same lines.
    pub fn assemble(&self, ctx: &C) -> AssembledDocument {
        let mut lines: Vec<LineItem> = Vec::new();
        for (_name, calc) in &self.calculators {
            let mut produced = calc(ctx, &lines);
            lines.append(&mut produced);
        }
        AssembledDocument { lines }
    }
}

/// The output of a chain: the ordered line items and aggregate queries over
/// them.
#[derive(Debug, Clone, Default)]
pub struct AssembledDocument {
    pub lines: Vec<LineItem>,
}

impl AssembledDocument {
    /// The document total: signed sum of all line amounts.
    pub fn total(&self) -> Decimal {
        LineItem::sum(&self.lines)
    }
    /// `f64` of the total, for display.
    pub fn total_f64(&self) -> f64 {
        self.total().to_f64().unwrap_or(0.0)
    }
    /// Sum of lines of one type.
    pub fn subtotal(&self, line_type: &str) -> Decimal {
        self.lines
            .iter()
            .filter(|l| l.line_type == line_type)
            .map(|l| l.amount)
            .sum()
    }
    /// Lines of one type.
    pub fn lines_of<'a>(&'a self, line_type: &'a str) -> impl Iterator<Item = &'a LineItem> {
        self.lines.iter().filter(move |l| l.line_type == line_type)
    }
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use uuid::Uuid;

    struct Ctx {
        base: Decimal,
        adjustments: Vec<AdjustmentResult>,
    }

    #[test]
    fn chain_is_additive_and_order_aware() {
        let ctx = Ctx {
            base: dec!(200),
            adjustments: vec![AdjustmentResult {
                rule_id: Uuid::from_u128(9),
                rule_version: 3,
                rule_name: "high-usage rebate".into(),
                adjustment_type: "rebate".into(),
                amount: dec!(-10),
                reason_code: Some("R1".into()),
            }],
        };

        let chain = CalculatorChain::new()
            .add("base", |c: &Ctx, _| vec![LineItem::new("base_tariff", "Base", c.base)])
            .add("adjustments", |c: &Ctx, _| {
                c.adjustments.iter().map(LineItem::from_adjustment).collect()
            })
            // Penalty is 2% of the running subtotal — depends on earlier lines.
            .add("penalty", |_c, sofar| {
                let sub = LineItem::sum(sofar);
                vec![LineItem::new("penalty", "Late penalty", sub * dec!(0.02))]
            });

        assert_eq!(chain.len(), 3);
        let doc = chain.assemble(&ctx);

        // base 200 + rebate -10 = 190 subtotal, +2% penalty (3.80) = 193.80
        assert_eq!(doc.subtotal("base_tariff"), dec!(200));
        assert_eq!(doc.subtotal("rebate"), dec!(-10));
        assert_eq!(doc.subtotal("penalty"), dec!(3.80));
        assert_eq!(doc.total(), dec!(193.80));
        assert_eq!(doc.lines.len(), 3);

        // Adjustment provenance survives into the line.
        let rebate = doc.lines_of("rebate").next().unwrap();
        assert_eq!(rebate.source_reference.as_deref(), Some(&*Uuid::from_u128(9).to_string()));
        assert_eq!(rebate.meta["rule_version"], 3);
    }

    #[test]
    fn empty_chain_yields_empty_document() {
        let chain: CalculatorChain<Ctx> = CalculatorChain::new();
        let doc = chain.assemble(&Ctx { base: dec!(0), adjustments: vec![] });
        assert!(doc.is_empty());
        assert_eq!(doc.total(), Decimal::ZERO);
    }

    #[test]
    fn line_builders() {
        let l = LineItem::new("icpt", "ICPT surcharge", dec!(5))
            .with_quantity(dec!(100))
            .with_source("reading-1");
        assert_eq!(l.quantity, Some(dec!(100)));
        assert_eq!(l.source_reference.as_deref(), Some("reading-1"));
    }
}
