//! No-code automation rules (Initiative #3).
//!
//! A rule says: *when a record of `model_name` is created/updated (and,
//! optionally, matches a condition), run an action.* Rules are rows an admin
//! authors in the UI — no Rust, no deploy. [`run_rules`] is invoked from the
//! record-save path after a change lands.
//!
//! **Safety.** Every dynamic identifier (the model's table, the condition
//! field, the action field) is validated against the code-derived registry
//! (`ir_model` / `ir_model_field`, real columns only) before it touches SQL —
//! so a rule can only read/write a real, registered column of its own model.
//! Values are always bound, never interpolated. Actions write the row directly
//! (not through the form-save path), so a `set_field` rule cannot re-trigger
//! itself into a loop.
//!
//! v1 scope: one optional condition and the `set_field` action. Multi-condition
//! (AND/OR) rules, and richer actions (create activity, send mail, fire
//! webhook), layer on top later.

use std::collections::HashMap;

use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Comparison operators offered to rule authors, as `(code, label)`.
pub const OPERATORS: &[(&str, &str)] = &[
    ("eq", "is equal to"),
    ("ne", "is not equal to"),
    ("gt", "is greater than"),
    ("ge", "is greater or equal to"),
    ("lt", "is less than"),
    ("le", "is less or equal to"),
    ("contains", "contains"),
    ("is_empty", "is empty"),
    ("is_not_empty", "is not empty"),
];

/// Trigger events, as `(code, label)`.
pub const TRIGGERS: &[(&str, &str)] = &[("create", "is created"), ("update", "is updated")];

/// One automation rule.
#[derive(Debug, Clone)]
pub struct AutomationRule {
    pub id: Uuid,
    pub name: String,
    pub model_name: String,
    pub trigger_event: String,
    pub condition_field: Option<String>,
    pub condition_op: Option<String>,
    pub condition_value: Option<String>,
    pub action_field: String,
    pub action_value: Option<String>,
    pub active: bool,
}

fn row_to_rule(r: sqlx::postgres::PgRow) -> AutomationRule {
    AutomationRule {
        id: r.get("id"),
        name: r.get("name"),
        model_name: r.get("model_name"),
        trigger_event: r.get("trigger_event"),
        condition_field: r.try_get("condition_field").ok().flatten(),
        condition_op: r.try_get("condition_op").ok().flatten(),
        condition_value: r.try_get("condition_value").ok().flatten(),
        action_field: r.get("action_field"),
        action_value: r.try_get("action_value").ok().flatten(),
        active: r.get("active"),
    }
}

/// A defensive identifier check (belt-and-suspenders alongside the registry
/// allow-list): lowercase snake identifiers only.
fn ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The real (non-custom) columns of a model, as `name -> field_type`, from the
/// registry. This is the allow-list a rule's fields must belong to. Empty on
/// any error or unknown model.
async fn registered_fields(db: &PgPool, model: &str) -> HashMap<String, String> {
    let rows = sqlx::query(
        "SELECT f.name, f.field_type FROM ir_model_field f \
         JOIN ir_model m ON m.id = f.model_id \
         WHERE m.name = $1 AND f.is_custom = false",
    )
    .bind(model)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.into_iter().map(|r| (r.get("name"), r.get("field_type"))).collect()
}

/// The physical table for a model, if registered and a safe identifier.
async fn model_table(db: &PgPool, model: &str) -> Option<String> {
    let t: Option<String> = sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1 AND is_active = true")
        .bind(model)
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
    t.filter(|t| ident(t))
}

/// Map an `ir_model_field.field_type` to the SQL cast a text-bound value needs
/// to compare/assign against that column.
fn sql_cast(field_type: &str) -> &'static str {
    match field_type {
        "boolean" => "::boolean",
        "integer" => "::bigint",
        "float" | "decimal" | "monetary" | "number" => "::numeric",
        "date" => "::date",
        "datetime" => "::timestamptz",
        "uuid" | "many2one" => "::uuid",
        _ => "", // string / text / selection / char
    }
}

/// SQL comparison operator for a UI operator code (the six ordered comparisons).
fn cmp_sql(op: &str) -> Option<&'static str> {
    match op {
        "eq" => Some("="),
        "ne" => Some("<>"),
        "gt" => Some(">"),
        "ge" => Some(">="),
        "lt" => Some("<"),
        "le" => Some("<="),
        _ => None,
    }
}

fn is_valid_op(op: &str) -> bool {
    OPERATORS.iter().any(|(c, _)| *c == op)
}

// ── CRUD ────────────────────────────────────────────────────────────────────

pub async fn list_all(db: &PgPool) -> Vec<AutomationRule> {
    let rows = sqlx::query(
        "SELECT id, name, model_name, trigger_event, condition_field, condition_op, \
                condition_value, action_field, action_value, active \
         FROM automation_rule ORDER BY model_name, name",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.into_iter().map(row_to_rule).collect()
}

/// Active rules for a `(model, trigger)`, used on the hot save path. Resilient:
/// empty on any error (e.g. a DB predating migration 138).
pub async fn rules_for(db: &PgPool, model: &str, trigger: &str) -> Vec<AutomationRule> {
    let rows = sqlx::query(
        "SELECT id, name, model_name, trigger_event, condition_field, condition_op, \
                condition_value, action_field, action_value, active \
         FROM automation_rule \
         WHERE model_name = $1 AND trigger_event = $2 AND active = true",
    )
    .bind(model)
    .bind(trigger)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.into_iter().map(row_to_rule).collect()
}

/// Validate and create a rule.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    db: &PgPool,
    name: &str,
    model: &str,
    trigger: &str,
    condition_field: Option<&str>,
    condition_op: Option<&str>,
    condition_value: Option<&str>,
    action_field: &str,
    action_value: Option<&str>,
    created_by: Option<Uuid>,
) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("A rule needs a name.".into());
    }
    if !TRIGGERS.iter().any(|(c, _)| *c == trigger) {
        return Err("Invalid trigger.".into());
    }
    let fields = registered_fields(db, model).await;
    if fields.is_empty() {
        return Err(format!("Unknown or empty model {model:?}."));
    }
    if !fields.contains_key(action_field) {
        return Err(format!("{action_field:?} is not a field of {model}."));
    }
    let condition_field = condition_field.filter(|s| !s.trim().is_empty());
    if let Some(cf) = condition_field {
        if !fields.contains_key(cf) {
            return Err(format!("Condition field {cf:?} is not a field of {model}."));
        }
        match condition_op {
            Some(op) if is_valid_op(op) => {}
            _ => return Err("Choose a valid condition operator.".into()),
        }
    }

    sqlx::query(
        "INSERT INTO automation_rule \
            (name, model_name, trigger_event, condition_field, condition_op, condition_value, \
             action_type, action_field, action_value, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, 'set_field', $7, $8, $9)",
    )
    .bind(name.trim())
    .bind(model)
    .bind(trigger)
    .bind(condition_field)
    .bind(condition_op.filter(|_| condition_field.is_some()))
    .bind(condition_value.filter(|_| condition_field.is_some()))
    .bind(action_field)
    .bind(action_value)
    .bind(created_by)
    .execute(db)
    .await
    .map_err(|e| format!("save failed: {e}"))?;
    Ok(())
}

pub async fn delete(db: &PgPool, id: Uuid) -> Result<(), String> {
    sqlx::query("DELETE FROM automation_rule WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(|e| format!("delete failed: {e}"))?;
    Ok(())
}

// ── Execution ───────────────────────────────────────────────────────────────

/// Does `record_id` satisfy the rule's optional condition? A rule with no
/// condition always matches. All identifiers are validated against `fields`
/// (the registry allow-list) before use.
async fn condition_matches(
    db: &PgPool,
    table: &str,
    fields: &HashMap<String, String>,
    rule: &AutomationRule,
    record_id: Uuid,
) -> bool {
    let Some(field) = rule.condition_field.as_deref() else { return true };
    let Some(op) = rule.condition_op.as_deref() else { return true };
    let Some(ftype) = fields.get(field) else { return false };
    if !ident(field) {
        return false;
    }
    let cast = sql_cast(ftype);
    let value = rule.condition_value.clone().unwrap_or_default();

    let (predicate, bind): (String, Option<String>) = match op {
        "is_empty" => (format!("({field} IS NULL OR {field}::text = '')"), None),
        "is_not_empty" => (format!("({field} IS NOT NULL AND {field}::text <> '')"), None),
        "contains" => (format!("{field}::text ILIKE $2"), Some(format!("%{value}%"))),
        cmp_code => match cmp_sql(cmp_code) {
            Some(sql_op) => (format!("{field} {sql_op} $2{cast}"), Some(value)),
            None => return false,
        },
    };

    let sql = format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id = $1 AND {predicate})");
    let mut q = sqlx::query_scalar::<_, bool>(&sql).bind(record_id);
    if let Some(v) = bind {
        q = q.bind(v);
    }
    q.fetch_one(db).await.unwrap_or(false)
}

/// Evaluate every active rule for `(model, trigger)` against the record and
/// apply matching actions. Returns the names of the rules that fired. Never
/// panics; a malformed rule is skipped. Best-effort: safe to call unconditionally
/// on the save path (no-op when there are no rules).
pub async fn run_rules(db: &PgPool, model: &str, trigger: &str, record_id: Uuid) -> Vec<String> {
    let rules = rules_for(db, model, trigger).await;
    if rules.is_empty() {
        return Vec::new();
    }
    let Some(table) = model_table(db, model).await else { return Vec::new() };
    let fields = registered_fields(db, model).await;

    let mut fired = Vec::new();
    for rule in rules {
        // Action field must be a real, registered column.
        let Some(ftype) = fields.get(&rule.action_field) else { continue };
        if !ident(&rule.action_field) {
            continue;
        }
        if !condition_matches(db, &table, &fields, &rule, record_id).await {
            continue;
        }

        // set_field: assign the (text-bound, cast) value directly to the row.
        let cast = sql_cast(ftype);
        let sql = format!("UPDATE {table} SET {} = $1{cast} WHERE id = $2", rule.action_field);
        let value = rule.action_value.clone().filter(|v| !v.is_empty());
        match sqlx::query(&sql).bind(value).bind(record_id).execute(db).await {
            Ok(_) => fired.push(rule.name.clone()),
            Err(e) => tracing::warn!("automation rule {:?} action failed: {}", rule.name, e),
        }
    }
    if !fired.is_empty() {
        tracing::info!(model, trigger, count = fired.len(), "automation rules fired");
    }
    fired
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn casts_by_type() {
        assert_eq!(sql_cast("boolean"), "::boolean");
        assert_eq!(sql_cast("monetary"), "::numeric");
        assert_eq!(sql_cast("many2one"), "::uuid");
        assert_eq!(sql_cast("string"), "");
    }

    #[test]
    fn operator_mapping() {
        assert_eq!(cmp_sql("ne"), Some("<>"));
        assert_eq!(cmp_sql("ge"), Some(">="));
        assert!(cmp_sql("contains").is_none());
        assert!(is_valid_op("contains"));
        assert!(!is_valid_op("bogus"));
    }

    #[test]
    fn identifier_guard() {
        assert!(ident("state"));
        assert!(ident("x_priority"));
        assert!(!ident("1bad"));
        assert!(!ident("drop table"));
        assert!(!ident("a\";--"));
    }

    /// Full loop against a real DB. Runs only when `VORTEX_TEST_DB` points at a
    /// migrated throwaway DB; otherwise skips.
    #[tokio::test]
    async fn run_rules_against_db() {
        let Ok(url) = std::env::var("VORTEX_TEST_DB") else {
            eprintln!("skip run_rules_against_db: VORTEX_TEST_DB unset");
            return;
        };
        let db = PgPool::connect(&url).await.expect("connect");

        // A registered contacts row to act on.
        let rid = Uuid::new_v4();
        sqlx::query("INSERT INTO contacts (id, name, contact_type, active, company_id) \
                     VALUES ($1, 'Acme', 'customer', true, (SELECT id FROM companies LIMIT 1))")
            .bind(rid).execute(&db).await.expect("insert contact");

        // Rule: when a contact is updated AND contact_type = 'customer', set city = 'VIP'.
        create(&db, "Flag customers", "contacts", "update",
               Some("contact_type"), Some("eq"), Some("customer"),
               "city", Some("VIP"), None).await.expect("create rule");

        // Non-matching rule (different type) must not fire.
        create(&db, "Never", "contacts", "update",
               Some("contact_type"), Some("eq"), Some("supplier"),
               "city", Some("NOPE"), None).await.expect("create rule 2");

        let fired = run_rules(&db, "contacts", "update", rid).await;
        assert_eq!(fired, vec!["Flag customers".to_string()], "only the matching rule fires");

        let city: Option<String> = sqlx::query_scalar("SELECT city FROM contacts WHERE id = $1")
            .bind(rid).fetch_one(&db).await.unwrap();
        assert_eq!(city.as_deref(), Some("VIP"), "action applied");

        // Cleanup.
        sqlx::query("DELETE FROM automation_rule WHERE model_name = 'contacts'").execute(&db).await.ok();
        sqlx::query("DELETE FROM contacts WHERE id = $1").bind(rid).execute(&db).await.ok();
    }
}
