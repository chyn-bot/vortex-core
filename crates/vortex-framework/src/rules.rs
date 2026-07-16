//! Versioned rules & adjustment engine.
//!
//! Exception logic — rebates, overrides, surcharges — is where a billing engine
//! (and any comparable domain) accretes the most churn and the most defects, so
//! this engine holds three properties that hardcoded `if` branches cannot:
//!
//! 1. **Rules are data.** A rule is a stored condition + a stored amount
//!    formula, authored by an analyst, not a code change.
//! 2. **Versions are immutable once published.** Editing makes a new version;
//!    a published version never changes. A record that recorded "evaluated
//!    against version 4" reproduces identically forever, even after version 5
//!    ships — the regression guarantee the IWK scope demands for court-defensible
//!    billing.
//! 3. **Evaluation is a pure function** of `(rule set version, input document)`
//!    and records *which rule and version* produced every adjustment — and every
//!    no-op — so a bill is fully explainable.
//!
//! It is **core and industry-neutral**: it names no tariff, rebate, or
//! regulator. A vertical authors the rules and names its own `adjustment_type`s;
//! the engine only evaluates. It is distinct from the two other rule mechanisms
//! in core — Cedar (*authorization*) and automation rules (*on-save side
//! effects*) — because it produces *calculation adjustments*, which neither
//! does.
//!
//! # The two halves
//!
//! - The **evaluator** ([`Condition`], [`Amount`], [`evaluate`]) is pure and has
//!   no database dependency — trivially testable and the reproducible heart.
//! - The **store** ([`create_version`], [`add_rule`], [`publish`], [`load`],
//!   [`latest_published`], [`load_version`]) persists and versions rule sets.
//!
//! # Condition / Amount JSON
//!
//! Conditions and amounts serialize to compact tagged JSON, stored in JSONB:
//!
//! ```json
//! // condition: fires when reading > 100 AND tariff_class == "domestic"
//! {"op":"and","all":[
//!   {"op":"gt","field":"reading","value":100},
//!   {"op":"eq","field":"tariff_class","value":"domestic"}
//! ]}
//! // amount: 5% of the base_charge field
//! {"kind":"percent_of","field":"base_charge","percent":"5"}
//! ```
//!
//! Field references are dot-paths into the input document
//! (`meter.reading` descends objects). Missing fields make ordering comparisons
//! false and numeric amounts zero — never a panic.

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::postgres::PgPool;
use sqlx::Row;
use std::str::FromStr;
use uuid::Uuid;

// ─── Condition AST (pure evaluator) ──────────────────────────────────────

/// A boolean condition over an input document. Serializes to `{"op": …}` JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Condition {
    /// Always fires. The default for a rule with no gating.
    Always {},
    /// Negation.
    Not { of: Box<Condition> },
    /// All sub-conditions must hold (empty ⇒ true).
    And { all: Vec<Condition> },
    /// Any sub-condition holds (empty ⇒ false).
    Or { any: Vec<Condition> },
    /// `field == value` (JSON equality, numbers compared numerically).
    Eq { field: String, value: Value },
    /// `field != value`.
    Ne { field: String, value: Value },
    /// `field > value` (both must be numeric, else false).
    Gt { field: String, value: Value },
    /// `field >= value`.
    Gte { field: String, value: Value },
    /// `field < value`.
    Lt { field: String, value: Value },
    /// `field <= value`.
    Lte { field: String, value: Value },
    /// `field` equals one of `values`.
    In { field: String, values: Vec<Value> },
    /// `field` is present and not null.
    Exists { field: String },
}

/// Resolve a dot-path (`a.b.c`) into a JSON document.
fn resolve<'a>(field: &str, input: &'a Value) -> Option<&'a Value> {
    let mut cur = input;
    for seg in field.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Numeric view of a JSON value: a JSON number, or a string that parses as a
/// decimal. `None` for anything else (so ordering comparisons stay false).
fn as_decimal(v: &Value) -> Option<Decimal> {
    match v {
        Value::Number(n) => n.as_f64().and_then(Decimal::from_f64_retain),
        Value::String(s) => Decimal::from_str(s.trim()).ok(),
        _ => None,
    }
}

/// JSON equality with numeric normalization: `1` == `1.0` == `"1"`.
fn values_eq(a: &Value, b: &Value) -> bool {
    if let (Some(da), Some(db)) = (as_decimal(a), as_decimal(b)) {
        return da == db;
    }
    a == b
}

impl Condition {
    /// Evaluate against `input`. Pure and total — never panics; a malformed or
    /// missing field simply fails to match.
    pub fn eval(&self, input: &Value) -> bool {
        match self {
            Condition::Always {} => true,
            Condition::Not { of } => !of.eval(input),
            Condition::And { all } => all.iter().all(|c| c.eval(input)),
            Condition::Or { any } => any.iter().any(|c| c.eval(input)),
            Condition::Eq { field, value } => {
                resolve(field, input).is_some_and(|f| values_eq(f, value))
            }
            Condition::Ne { field, value } => {
                // Absent field ≠ value ⇒ true (it is not equal).
                resolve(field, input).map_or(true, |f| !values_eq(f, value))
            }
            Condition::Gt { field, value }
            | Condition::Gte { field, value }
            | Condition::Lt { field, value }
            | Condition::Lte { field, value } => {
                let (Some(f), Some(v)) =
                    (resolve(field, input).and_then(as_decimal), as_decimal(value))
                else {
                    return false;
                };
                match self {
                    Condition::Gt { .. } => f > v,
                    Condition::Gte { .. } => f >= v,
                    Condition::Lt { .. } => f < v,
                    Condition::Lte { .. } => f <= v,
                    _ => unreachable!(),
                }
            }
            Condition::In { field, values } => {
                resolve(field, input).is_some_and(|f| values.iter().any(|v| values_eq(f, v)))
            }
            Condition::Exists { field } => {
                resolve(field, input).is_some_and(|v| !v.is_null())
            }
        }
    }
}

// ─── Amount AST (pure evaluator) ─────────────────────────────────────────

/// How much an adjustment is worth, given the input document. Serializes to
/// `{"kind": …}` JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Amount {
    /// A constant.
    Fixed { value: Decimal },
    /// The numeric value of a field (0 if missing/non-numeric).
    Field { field: String },
    /// `percent`% of a numeric field.
    PercentOf { field: String, percent: Decimal },
}

impl Amount {
    /// Compute the amount. Total — a missing or non-numeric field yields zero,
    /// never an error, so a rule can never blow up a run.
    pub fn eval(&self, input: &Value) -> Decimal {
        match self {
            Amount::Fixed { value } => *value,
            Amount::Field { field } => resolve(field, input)
                .and_then(as_decimal)
                .unwrap_or(Decimal::ZERO),
            Amount::PercentOf { field, percent } => {
                let base = resolve(field, input)
                    .and_then(as_decimal)
                    .unwrap_or(Decimal::ZERO);
                base * *percent / Decimal::from(100)
            }
        }
    }
}

// ─── Rules + evaluation output ───────────────────────────────────────────

/// One authored rule: a gating condition and the adjustment it produces.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: Uuid,
    pub seq: i32,
    pub name: String,
    pub condition: Condition,
    pub adjustment_type: String,
    pub amount: Amount,
    pub reason_code: Option<String>,
    pub active: bool,
}

/// One produced adjustment. Carries `rule_id` and `rule_version` so the bill it
/// lands on records exactly what produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct AdjustmentResult {
    pub rule_id: Uuid,
    pub rule_version: i32,
    pub rule_name: String,
    pub adjustment_type: String,
    pub amount: Decimal,
    pub reason_code: Option<String>,
}

/// A record that a rule was evaluated — fired or not. The IWK contract requires
/// recording `rule_id`/`rule_version` for *every* evaluation, even a no-op, so a
/// bill's non-adjustment is as explainable as its adjustment.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleFiring {
    pub rule_id: Uuid,
    pub rule_version: i32,
    pub rule_name: String,
    pub fired: bool,
}

/// The full, deterministic result of evaluating a rule set version against one
/// input: the adjustments produced, plus the firing trace over every rule.
#[derive(Debug, Clone, Default)]
pub struct EvalOutcome {
    pub adjustments: Vec<AdjustmentResult>,
    pub trace: Vec<RuleFiring>,
}

/// Evaluate `rules` (of rule set `version`) against `input`, in `seq` order.
/// Pure: same version + same input ⇒ same output, always. Inactive rules are
/// traced as not-fired and produce nothing.
pub fn evaluate(version: i32, rules: &[Rule], input: &Value) -> EvalOutcome {
    let mut out = EvalOutcome::default();
    for r in rules {
        let fired = r.active && r.condition.eval(input);
        out.trace.push(RuleFiring {
            rule_id: r.id,
            rule_version: version,
            rule_name: r.name.clone(),
            fired,
        });
        if fired {
            out.adjustments.push(AdjustmentResult {
                rule_id: r.id,
                rule_version: version,
                rule_name: r.name.clone(),
                adjustment_type: r.adjustment_type.clone(),
                amount: r.amount.eval(input),
                reason_code: r.reason_code.clone(),
            });
        }
    }
    out
}

impl EvalOutcome {
    /// Signed sum of all produced adjustment amounts.
    pub fn net_amount(&self) -> Decimal {
        self.adjustments.iter().map(|a| a.amount).sum()
    }
    /// Convenience: `f64` of [`net_amount`](Self::net_amount) for display.
    pub fn net_f64(&self) -> f64 {
        self.net_amount().to_f64().unwrap_or(0.0)
    }
}

// ─── Store / versioning ──────────────────────────────────────────────────

/// A rule set version header.
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub id: Uuid,
    pub code: String,
    pub version: i32,
    pub status: String,
    pub title: String,
}

impl RuleSet {
    pub fn is_published(&self) -> bool {
        self.status == "published"
    }
}

/// Fields for a new rule.
#[derive(Debug, Clone)]
pub struct NewRule {
    pub seq: i32,
    pub name: String,
    pub condition: Condition,
    pub adjustment_type: String,
    pub amount: Amount,
    pub reason_code: Option<String>,
}

/// Create a new `draft` version of rule set `code`, at the next version number.
pub async fn create_version(
    pool: &PgPool,
    code: &str,
    title: &str,
) -> Result<RuleSet, String> {
    let row = sqlx::query(
        "INSERT INTO rule_set (code, version, title) \
         VALUES ($1, COALESCE((SELECT MAX(version) FROM rule_set WHERE code=$1),0)+1, $2) \
         RETURNING id, code, version, status, title",
    )
    .bind(code)
    .bind(title)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("create_version failed: {e}"))?;
    Ok(RuleSet {
        id: row.get("id"),
        code: row.get("code"),
        version: row.get("version"),
        status: row.get("status"),
        title: row.get("title"),
    })
}

/// Add a rule to a `draft` version. Rejects if the version is already published
/// — published versions are immutable, which is what makes them reproducible.
pub async fn add_rule(
    pool: &PgPool,
    rule_set_id: Uuid,
    rule: NewRule,
) -> Result<Uuid, String> {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM rule_set WHERE id=$1")
            .bind(rule_set_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("add_rule: load set failed: {e}"))?;
    match status.as_deref() {
        None => return Err(format!("add_rule: rule set {rule_set_id} not found")),
        Some("draft") => {}
        Some(other) => {
            return Err(format!(
                "add_rule: rule set {rule_set_id} is '{other}', not editable"
            ))
        }
    }
    let condition = serde_json::to_value(&rule.condition)
        .map_err(|e| format!("add_rule: bad condition: {e}"))?;
    let amount =
        serde_json::to_value(&rule.amount).map_err(|e| format!("add_rule: bad amount: {e}"))?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO rule (rule_set_id, seq, name, condition, adjustment_type, amount, reason_code) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id",
    )
    .bind(rule_set_id)
    .bind(rule.seq)
    .bind(&rule.name)
    .bind(&condition)
    .bind(&rule.adjustment_type)
    .bind(&amount)
    .bind(&rule.reason_code)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("add_rule insert failed: {e}"))?;
    Ok(id)
}

/// Publish a `draft` version: freeze it immutable. Idempotent for an
/// already-published set; errors if the set is missing or archived.
pub async fn publish(pool: &PgPool, rule_set_id: Uuid) -> Result<(), String> {
    let res = sqlx::query(
        "UPDATE rule_set SET status='published', published_at=NOW() \
         WHERE id=$1 AND status='draft'",
    )
    .bind(rule_set_id)
    .execute(pool)
    .await
    .map_err(|e| format!("publish failed: {e}"))?;
    if res.rows_affected() == 0 {
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM rule_set WHERE id=$1")
                .bind(rule_set_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| format!("publish: status check failed: {e}"))?;
        match status.as_deref() {
            Some("published") => {} // idempotent
            Some(other) => return Err(format!("publish: rule set is '{other}'")),
            None => return Err(format!("publish: rule set {rule_set_id} not found")),
        }
    }
    Ok(())
}

/// Like [`publish`], but also writes a WORM audit event attributing the publish
/// to `user`. Publishing a rule version changes what every subsequent run
/// computes, so it is a governance action a regulated deployment must be able to
/// attribute — hence the audited entry point for UI/admin callers.
pub async fn publish_audited(
    state: &crate::state::AppState,
    user: &crate::auth::AuthUser,
    pool: &PgPool,
    rule_set_id: Uuid,
) -> Result<(), String> {
    publish(pool, rule_set_id).await?;
    // Include code/version in the event for a human-readable ledger entry.
    let meta = sqlx::query("SELECT code, version FROM rule_set WHERE id=$1")
        .bind(rule_set_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
    let (code, version) = meta
        .map(|r| (r.get::<String, _>("code"), r.get::<i32, _>("version")))
        .unwrap_or_default();
    crate::audit_events::emit(
        state,
        user,
        "rule_set.published",
        "rule_set",
        rule_set_id.to_string(),
        serde_json::json!({ "code": code, "version": version }),
    )
    .await;
    Ok(())
}

fn row_to_rule(r: &sqlx::postgres::PgRow) -> Result<Rule, String> {
    let condition: Value = r.get("condition");
    let amount: Value = r.get("amount");
    Ok(Rule {
        id: r.get("id"),
        seq: r.get("seq"),
        name: r.get("name"),
        condition: serde_json::from_value(condition)
            .map_err(|e| format!("rule condition parse failed: {e}"))?,
        adjustment_type: r.get("adjustment_type"),
        amount: serde_json::from_value(amount)
            .map_err(|e| format!("rule amount parse failed: {e}"))?,
        reason_code: r.try_get("reason_code").ok().flatten(),
        active: r.get("active"),
    })
}

async fn load_rules(pool: &PgPool, rule_set_id: Uuid) -> Result<Vec<Rule>, String> {
    let rows = sqlx::query(
        "SELECT id, seq, name, condition, adjustment_type, amount, reason_code, active \
         FROM rule WHERE rule_set_id=$1 ORDER BY seq, id",
    )
    .bind(rule_set_id)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("load_rules failed: {e}"))?;
    rows.iter().map(row_to_rule).collect()
}

fn row_to_set(r: &sqlx::postgres::PgRow) -> RuleSet {
    RuleSet {
        id: r.get("id"),
        code: r.get("code"),
        version: r.get("version"),
        status: r.get("status"),
        title: r.get("title"),
    }
}

/// Load a rule set version by id, with its rules in evaluation order.
pub async fn load(pool: &PgPool, rule_set_id: Uuid) -> Result<Option<(RuleSet, Vec<Rule>)>, String> {
    let row = sqlx::query("SELECT id, code, version, status, title FROM rule_set WHERE id=$1")
        .bind(rule_set_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("load failed: {e}"))?;
    let Some(row) = row else { return Ok(None) };
    let set = row_to_set(&row);
    let rules = load_rules(pool, set.id).await?;
    Ok(Some((set, rules)))
}

/// The highest-versioned **published** set for `code` — what a live run loads.
pub async fn latest_published(
    pool: &PgPool,
    code: &str,
) -> Result<Option<(RuleSet, Vec<Rule>)>, String> {
    let row = sqlx::query(
        "SELECT id, code, version, status, title FROM rule_set \
         WHERE code=$1 AND status='published' ORDER BY version DESC LIMIT 1",
    )
    .bind(code)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("latest_published failed: {e}"))?;
    let Some(row) = row else { return Ok(None) };
    let set = row_to_set(&row);
    let rules = load_rules(pool, set.id).await?;
    Ok(Some((set, rules)))
}

/// Load a specific `(code, version)` — how a historical record is reproduced
/// against the exact rules that applied when it was first calculated.
pub async fn load_version(
    pool: &PgPool,
    code: &str,
    version: i32,
) -> Result<Option<(RuleSet, Vec<Rule>)>, String> {
    let row = sqlx::query(
        "SELECT id, code, version, status, title FROM rule_set WHERE code=$1 AND version=$2",
    )
    .bind(code)
    .bind(version)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("load_version failed: {e}"))?;
    let Some(row) = row else { return Ok(None) };
    let set = row_to_set(&row);
    let rules = load_rules(pool, set.id).await?;
    Ok(Some((set, rules)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use serde_json::json;

    fn rule(id_seed: u128, name: &str, cond: Condition, amt: Amount) -> Rule {
        Rule {
            id: Uuid::from_u128(id_seed),
            seq: id_seed as i32,
            name: name.to_string(),
            condition: cond,
            adjustment_type: "rebate".into(),
            amount: amt,
            reason_code: Some("R1".into()),
            active: true,
        }
    }

    #[test]
    fn condition_comparisons_and_logic() {
        let input = json!({"reading": 150, "tariff_class": "domestic", "meta": {"eligible": true}});

        assert!(Condition::Gt { field: "reading".into(), value: json!(100) }.eval(&input));
        assert!(!Condition::Gt { field: "reading".into(), value: json!(200) }.eval(&input));
        assert!(Condition::Eq { field: "tariff_class".into(), value: json!("domestic") }.eval(&input));
        assert!(Condition::Exists { field: "meta.eligible".into() }.eval(&input));
        assert!(!Condition::Exists { field: "meta.missing".into() }.eval(&input));

        // Nested path + numeric-string coercion.
        let coerce = json!({"amt": "42.5"});
        assert!(Condition::Gte { field: "amt".into(), value: json!(42) }.eval(&coerce));

        let both = Condition::And {
            all: vec![
                Condition::Gt { field: "reading".into(), value: json!(100) },
                Condition::Eq { field: "tariff_class".into(), value: json!("domestic") },
            ],
        };
        assert!(both.eval(&input));

        let either = Condition::Or {
            any: vec![
                Condition::Eq { field: "tariff_class".into(), value: json!("industrial") },
                Condition::Lt { field: "reading".into(), value: json!(1000) },
            ],
        };
        assert!(either.eval(&input));
        assert!(Condition::Not { of: Box::new(either) }.eval(&input) == false);
    }

    #[test]
    fn missing_field_never_panics() {
        let input = json!({});
        assert!(!Condition::Gt { field: "x.y.z".into(), value: json!(1) }.eval(&input));
        assert!(Condition::Ne { field: "x".into(), value: json!(1) }.eval(&input)); // absent ≠ 1
        assert_eq!(Amount::Field { field: "nope".into() }.eval(&input), Decimal::ZERO);
    }

    #[test]
    fn amount_kinds() {
        let input = json!({"base_charge": "200"});
        assert_eq!(Amount::Fixed { value: dec!(10) }.eval(&input), dec!(10));
        assert_eq!(Amount::Field { field: "base_charge".into() }.eval(&input), dec!(200));
        assert_eq!(
            Amount::PercentOf { field: "base_charge".into(), percent: dec!(5) }.eval(&input),
            dec!(10)
        );
    }

    #[test]
    fn evaluate_traces_every_rule_and_sums_fired() {
        let input = json!({"reading": 150, "base_charge": 200});
        let rules = vec![
            // fires: 5% rebate of base_charge = 10
            rule(1, "high-usage rebate",
                Condition::Gt { field: "reading".into(), value: json!(100) },
                Amount::PercentOf { field: "base_charge".into(), percent: dec!(5) }),
            // does not fire
            rule(2, "industrial override",
                Condition::Eq { field: "tariff_class".into(), value: json!("industrial") },
                Amount::Fixed { value: dec!(999) }),
        ];
        let out = evaluate(7, &rules, &input);

        // Trace records BOTH rules with the version, even the no-op.
        assert_eq!(out.trace.len(), 2);
        assert!(out.trace[0].fired && out.trace[0].rule_version == 7);
        assert!(!out.trace[1].fired && out.trace[1].rule_version == 7);

        // Only the fired rule produced an adjustment.
        assert_eq!(out.adjustments.len(), 1);
        assert_eq!(out.adjustments[0].amount, dec!(10));
        assert_eq!(out.adjustments[0].rule_version, 7);
        assert_eq!(out.net_amount(), dec!(10));
    }

    #[test]
    fn inactive_rule_never_fires() {
        let input = json!({"reading": 150});
        let mut r = rule(1, "x", Condition::Always {}, Amount::Fixed { value: dec!(5) });
        r.active = false;
        let out = evaluate(1, std::slice::from_ref(&r), &input);
        assert_eq!(out.adjustments.len(), 0);
        assert_eq!(out.trace.len(), 1);
        assert!(!out.trace[0].fired);
    }

    #[test]
    fn condition_json_roundtrips() {
        let c = Condition::And {
            all: vec![
                Condition::Gt { field: "reading".into(), value: json!(100) },
                Condition::Not { of: Box::new(Condition::Exists { field: "waived".into() }) },
            ],
        };
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(j["op"], "and");
        let back: Condition = serde_json::from_value(j).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn amount_json_shape() {
        let a = Amount::PercentOf { field: "base_charge".into(), percent: dec!(5) };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(j["kind"], "percent_of");
        assert_eq!(j["field"], "base_charge");
        let back: Amount = serde_json::from_value(j).unwrap();
        assert_eq!(back, a);
    }
}
