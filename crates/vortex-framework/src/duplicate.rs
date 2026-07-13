//! Record duplication — the platform-wide "Duplicate" action.
//!
//! Every transactional document (order, invoice, work order, …) wants an
//! Odoo-style *Duplicate* button: copy this record into a fresh, editable
//! draft. The copy mechanics are the same everywhere — clone the row,
//! regenerate identity, reset lifecycle columns, optionally clone child
//! lines — so they live here once and each module only declares what makes
//! its document special (which columns to reset, which sequence stamps the
//! new number, which line tables ride along).
//!
//! ```ignore
//! let new_id = DuplicateSpec::new("sales_order")
//!     .set("quote_number", json!(next_number))   // fresh sequence value
//!     .skip("state")                             // fall back to the DB default
//!     .copy_suffix("name")                       // "Widget" -> "Widget (copy)"
//!     .child(ChildCopy::new("sales_order_line", "order_id")
//!         .set("qty_delivered", json!(0)))
//!     .execute(&db, source_id, Some(user.id))
//!     .await?;
//! ```
//!
//! Safety model — identical to the public API's write path (`api.rs`): the
//! copy touches only real, non-generated columns discovered from
//! `information_schema`, every dynamic identifier passes the conservative
//! `ident` check, and override *values* are bound as a single jsonb
//! parameter and cast to each column's `udt_name` — never interpolated.
//!
//! What is never copied: `id` (fresh UUID), `created_at` / `updated_at`
//! (DB defaults), `created_by` (set to the duplicating user). Chatter,
//! attachments and audit history belong to the source record and stay
//! there; callers write a fresh audit entry for the copy instead.

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::{ident, table_columns};

/// Declarative description of how to duplicate one row of `table`,
/// optionally with child line tables. Build with the fluent methods, then
/// [`execute`](DuplicateSpec::execute).
pub struct DuplicateSpec {
    table: String,
    /// Columns left out of the copy entirely — the DB default applies
    /// (e.g. `state` falls back to `'draft'`, a nullable `code` to NULL).
    skip: Vec<String>,
    /// Columns overridden with a caller-supplied value (bound, cast).
    set: serde_json::Map<String, Value>,
    /// Text columns that get " (copy)" appended, Odoo-style.
    suffix: Vec<String>,
    /// Child tables cloned along with the parent.
    children: Vec<ChildCopy>,
    /// Caller-chosen id for the new record (defaults to a fresh v7 UUID).
    /// Useful when an override must reference the new id (e.g. a
    /// self-referencing `root_quote_id`).
    new_id: Option<Uuid>,
}

/// One child (line) table cloned with the parent: every row whose
/// `parent_col` points at the source gets copied, re-pointed at the copy,
/// with a fresh id per row.
pub struct ChildCopy {
    table: String,
    parent_col: String,
    skip: Vec<String>,
    set: serde_json::Map<String, Value>,
}

impl ChildCopy {
    pub fn new(table: impl Into<String>, parent_col: impl Into<String>) -> Self {
        Self { table: table.into(), parent_col: parent_col.into(), skip: Vec::new(), set: serde_json::Map::new() }
    }

    /// Leave `col` out of the copy; the DB default applies.
    pub fn skip(mut self, col: impl Into<String>) -> Self {
        self.skip.push(col.into());
        self
    }

    /// Override `col` with `value` on every copied line (e.g. reset a
    /// fulfilment counter to zero).
    pub fn set(mut self, col: impl Into<String>, value: Value) -> Self {
        self.set.insert(col.into(), value);
        self
    }
}

impl DuplicateSpec {
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            skip: Vec::new(),
            set: serde_json::Map::new(),
            suffix: Vec::new(),
            children: Vec::new(),
            new_id: None,
        }
    }

    /// Leave `col` out of the copy; the DB default applies. Use for
    /// lifecycle columns (`state`), unique document numbers with no
    /// replacement value, and stored totals that get recomputed.
    pub fn skip(mut self, col: impl Into<String>) -> Self {
        self.skip.push(col.into());
        self
    }

    /// Override `col` with `value` on the copy (bound and cast to the
    /// column's real type — use for a freshly drawn sequence number).
    pub fn set(mut self, col: impl Into<String>, value: Value) -> Self {
        self.set.insert(col.into(), value);
        self
    }

    /// Append " (copy)" to a text column so the duplicate is
    /// distinguishable at a glance. Non-text columns are copied verbatim.
    pub fn copy_suffix(mut self, col: impl Into<String>) -> Self {
        self.suffix.push(col.into());
        self
    }

    /// Clone a child line table along with the parent.
    pub fn child(mut self, child: ChildCopy) -> Self {
        self.children.push(child);
        self
    }

    /// Fix the new record's id up front, so overrides can reference it.
    pub fn with_id(mut self, id: Uuid) -> Self {
        self.new_id = Some(id);
        self
    }

    /// Copy the row `source_id` (and declared children) inside one
    /// transaction. Returns the new record's id. `created_by` stamps the
    /// duplicating user when the table has that column.
    pub async fn execute(
        &self,
        db: &PgPool,
        source_id: Uuid,
        created_by: Option<Uuid>,
    ) -> Result<Uuid, String> {
        if !ident(&self.table) {
            return Err(format!("illegal table name '{}'", self.table));
        }
        for c in &self.children {
            if !ident(&c.table) || !ident(&c.parent_col) {
                return Err(format!("illegal child identifier on '{}'", c.table));
            }
        }

        let new_id = self.new_id.unwrap_or_else(Uuid::now_v7);

        let parent_cols = table_columns(db, &self.table).await;
        if parent_cols.is_empty() {
            return Err(format!("unknown table '{}'", self.table));
        }
        let plan = build_copy_plan(
            &self.table,
            &parent_cols,
            &self.skip,
            &self.set,
            &self.suffix,
            IdSource::Bound,
            None,
            created_by.is_some(),
        )?;

        let mut tx = db.begin().await.map_err(|e| format!("begin failed: {e}"))?;

        let inserted = bind_copy(&plan, new_id, source_id, created_by)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("duplicate insert failed: {e}"))?;
        let Some(_) = inserted else {
            return Err("source record not found".into());
        };

        for c in &self.children {
            let child_cols = table_columns(db, &c.table).await;
            if child_cols.is_empty() {
                return Err(format!("unknown child table '{}'", c.table));
            }
            let plan = build_copy_plan(
                &c.table,
                &child_cols,
                &c.skip,
                &c.set,
                &[],
                IdSource::Generated,
                Some(&c.parent_col),
                created_by.is_some(),
            )?;
            bind_copy(&plan, new_id, source_id, created_by)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| format!("duplicate of '{}' lines failed: {e}", c.table))?;
        }

        tx.commit().await.map_err(|e| format!("commit failed: {e}"))?;
        Ok(new_id)
    }
}

/// How the copy obtains its fresh primary key.
enum IdSource {
    /// The parent row: one known id, bound as `$1`.
    Bound,
    /// Child rows: one fresh id per copied row, generated in SQL.
    Generated,
}

/// A fully built copy statement plus which optional binds it references.
struct CopyPlan {
    sql: String,
    bind_overrides: Option<Value>,
    bind_created_by: bool,
}

/// Build the `INSERT INTO t (…) SELECT … FROM t WHERE …` statement.
///
/// Bind positions are fixed: `$1` = new/parent id, `$2` = source id,
/// `$3` = overrides jsonb (only when present), then the next slot =
/// `created_by` (only when stamped). For a child copy, `$1` is the new
/// *parent* id and `$2` matches rows via the FK column.
fn build_copy_plan(
    table: &str,
    columns: &std::collections::HashMap<String, String>,
    skip: &[String],
    set: &serde_json::Map<String, Value>,
    suffix: &[String],
    id_source: IdSource,
    parent_col: Option<&str>,
    stamp_created_by: bool,
) -> Result<CopyPlan, String> {
    for col in skip.iter().chain(suffix) {
        if !ident(col) {
            return Err(format!("illegal column name '{col}'"));
        }
    }
    for col in set.keys() {
        if !ident(col) {
            return Err(format!("illegal column name '{col}'"));
        }
        if !columns.contains_key(col) && !is_identity_col(col) {
            return Err(format!("unknown column '{col}' on '{table}'"));
        }
    }

    let mut cols: Vec<String> = Vec::new();
    let mut exprs: Vec<String> = Vec::new();

    cols.push("id".into());
    exprs.push(match id_source {
        IdSource::Bound => "$1".into(),
        IdSource::Generated => "gen_random_uuid()".into(),
    });

    let has_overrides = !set.is_empty();
    let overrides_param = 3; // reserved whenever overrides exist
    let created_by_param = if has_overrides { 4 } else { 3 };
    let stamp_created_by = stamp_created_by && columns.contains_key("created_by");

    for (col, udt) in sorted(columns) {
        let (col, udt) = (col.as_str(), udt.as_str());
        if is_identity_col(col) || skip.iter().any(|s| s == col) {
            continue;
        }
        if Some(col) == parent_col {
            cols.push(col.to_string());
            exprs.push("$1".into());
            continue;
        }
        if col == "created_by" {
            if stamp_created_by {
                cols.push(col.to_string());
                exprs.push(format!("${created_by_param}::uuid"));
            }
            continue;
        }
        if set.contains_key(col) {
            cols.push(col.to_string());
            exprs.push(cast_from_overrides(col, udt, overrides_param));
            continue;
        }
        if suffix.iter().any(|s| s == col) && is_text_udt(udt) {
            cols.push(col.to_string());
            exprs.push(format!("{col} || ' (copy)'"));
            continue;
        }
        cols.push(col.to_string());
        exprs.push(col.to_string());
    }

    let where_col = parent_col.unwrap_or("id");
    let sql = format!(
        "INSERT INTO {table} ({}) SELECT {} FROM {table} WHERE {where_col} = $2 RETURNING id",
        cols.join(", "),
        exprs.join(", "),
    );
    Ok(CopyPlan {
        sql,
        bind_overrides: has_overrides.then(|| Value::Object(set.clone())),
        bind_created_by: stamp_created_by,
    })
}

/// Attach a plan's binds in their fixed order.
fn bind_copy<'q>(
    plan: &'q CopyPlan,
    new_or_parent_id: Uuid,
    source_id: Uuid,
    created_by: Option<Uuid>,
) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, Uuid, sqlx::postgres::PgArguments> {
    let mut q = sqlx::query_scalar::<_, Uuid>(&plan.sql).bind(new_or_parent_id).bind(source_id);
    if let Some(overrides) = &plan.bind_overrides {
        q = q.bind(overrides);
    }
    if plan.bind_created_by {
        q = q.bind(created_by);
    }
    q
}

/// Columns the copy machinery owns outright — never copied, never
/// overridable by callers.
fn is_identity_col(col: &str) -> bool {
    matches!(col, "id" | "created_at" | "updated_at")
}

/// `($n->>'col')::udt` — extract one override from the bound jsonb and cast
/// it to the column's real type; JSON columns keep their structure.
fn cast_from_overrides(col: &str, udt: &str, param: usize) -> String {
    if udt == "jsonb" || udt == "json" {
        format!("(${param}->'{col}')::{udt}")
    } else {
        format!("(${param}->>'{col}')::{udt}")
    }
}

fn is_text_udt(udt: &str) -> bool {
    matches!(udt, "text" | "varchar" | "bpchar")
}

/// Deterministic column order — HashMap iteration order would otherwise
/// change the SQL text between calls.
fn sorted(columns: &std::collections::HashMap<String, String>) -> Vec<(&String, &String)> {
    let mut v: Vec<_> = columns.iter().collect();
    v.sort_by(|a, b| a.0.cmp(b.0));
    v
}

/// The standard header-area Duplicate button: a plain POST form, styled
/// like the other record actions. `action` is the module's duplicate
/// route, e.g. `/sales/orders/{id}/duplicate`.
pub fn duplicate_button(action: &str) -> String {
    format!(
        r#"<form method="POST" action="{}" class="inline m-0"><button type="submit" class="btn btn-sm btn-outline" title="Create a copy of this record">Duplicate</button></form>"#,
        crate::ui::html_escape(action),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cols(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs.iter().map(|(c, u)| (c.to_string(), u.to_string())).collect()
    }

    #[test]
    fn parent_copy_covers_all_columns_once() {
        let columns = cols(&[
            ("id", "uuid"),
            ("name", "varchar"),
            ("state", "varchar"),
            ("total", "numeric"),
            ("created_at", "timestamptz"),
            ("created_by", "uuid"),
        ]);
        let plan = build_copy_plan(
            "doc", &columns, &[], &serde_json::Map::new(), &[], IdSource::Bound, None, true,
        )
        .unwrap();
        assert_eq!(
            plan.sql,
            "INSERT INTO doc (id, created_by, name, state, total) \
             SELECT $1, $3::uuid, name, state, total FROM doc WHERE id = $2 RETURNING id"
        );
        assert!(plan.bind_overrides.is_none());
        assert!(plan.bind_created_by);
    }

    #[test]
    fn skip_set_and_suffix_shape_the_select() {
        let columns = cols(&[
            ("id", "uuid"),
            ("name", "text"),
            ("code", "varchar"),
            ("state", "varchar"),
            ("meta", "jsonb"),
        ]);
        let mut set = serde_json::Map::new();
        set.insert("code".into(), json!("SO/000042"));
        set.insert("meta".into(), json!({"k": 1}));
        let plan = build_copy_plan(
            "doc", &columns, &["state".into()], &set, &["name".into()],
            IdSource::Bound, None, false,
        )
        .unwrap();
        assert_eq!(
            plan.sql,
            "INSERT INTO doc (id, code, meta, name) \
             SELECT $1, ($3->>'code')::varchar, ($3->'meta')::jsonb, name || ' (copy)' \
             FROM doc WHERE id = $2 RETURNING id"
        );
        assert_eq!(plan.bind_overrides, Some(json!({"code": "SO/000042", "meta": {"k": 1}})));
        assert!(!plan.bind_created_by);
    }

    #[test]
    fn child_copy_generates_ids_and_repoints_the_fk() {
        let columns = cols(&[
            ("id", "uuid"),
            ("order_id", "uuid"),
            ("quantity", "numeric"),
            ("delivered", "numeric"),
        ]);
        let mut set = serde_json::Map::new();
        set.insert("delivered".into(), json!(0));
        let plan = build_copy_plan(
            "doc_line", &columns, &[], &set, &[], IdSource::Generated, Some("order_id"), false,
        )
        .unwrap();
        assert_eq!(
            plan.sql,
            "INSERT INTO doc_line (id, delivered, order_id, quantity) \
             SELECT gen_random_uuid(), ($3->>'delivered')::numeric, $1, quantity \
             FROM doc_line WHERE order_id = $2 RETURNING id"
        );
    }

    #[test]
    fn suffix_on_non_text_column_copies_verbatim() {
        let columns = cols(&[("id", "uuid"), ("amount", "numeric")]);
        let plan = build_copy_plan(
            "doc", &columns, &[], &serde_json::Map::new(), &["amount".into()],
            IdSource::Bound, None, false,
        )
        .unwrap();
        assert!(plan.sql.contains("SELECT $1, amount FROM"));
    }

    #[test]
    fn unknown_or_illegal_override_columns_are_rejected() {
        let columns = cols(&[("id", "uuid"), ("name", "text")]);
        let mut set = serde_json::Map::new();
        set.insert("nope".into(), json!(1));
        assert!(build_copy_plan(
            "doc", &columns, &[], &set, &[], IdSource::Bound, None, false
        )
        .is_err());

        let mut evil = serde_json::Map::new();
        evil.insert("name; DROP TABLE doc".into(), json!(1));
        assert!(build_copy_plan(
            "doc", &columns, &[], &evil, &[], IdSource::Bound, None, false
        )
        .is_err());
    }

    #[test]
    fn identity_columns_never_ride_along() {
        let columns = cols(&[
            ("id", "uuid"),
            ("created_at", "timestamptz"),
            ("updated_at", "timestamptz"),
            ("name", "text"),
        ]);
        let plan = build_copy_plan(
            "doc", &columns, &[], &serde_json::Map::new(), &[], IdSource::Bound, None, false,
        )
        .unwrap();
        assert_eq!(
            plan.sql,
            "INSERT INTO doc (id, name) SELECT $1, name FROM doc WHERE id = $2 RETURNING id"
        );
    }

    #[test]
    fn duplicate_button_escapes_the_action() {
        let html = duplicate_button("/x/1/duplicate\"><script>");
        assert!(!html.contains("<script>"));
        assert!(html.contains("method=\"POST\""));
    }
}
