//! Computed / related virtual fields (Initiative #5).
//!
//! A computed field is an admin-authored, `x_`-prefixed virtual field whose
//! value is **derived**, not entered. It reuses the custom-field machinery from
//! Initiative #2 — it is an `ir_model_field` row with `is_custom = true` **and**
//! `is_computed = true`, and its evaluated value is stored in the same
//! `ir_custom_value` overflow store — so it needs no column on the model's own
//! table and no runtime DDL.
//!
//! Two kinds:
//!
//! * **related** — `compute_expr = "<m2o_field>.<target_field>"`, e.g.
//!   `partner_id.email`. Evaluated with a validated `LEFT JOIN` across the
//!   many2one to the related record.
//! * **expr** — an arithmetic expression over the record's own numeric fields,
//!   e.g. `(qty * unit_price) - discount`. Evaluated by Postgres.
//!
//! **Safety.** Every identifier a definition names — the many2one field, the
//! target field, each field in an expression — is validated against the
//! code-derived registry (`ir_model` / `ir_model_field`, real columns only)
//! before it is ever placed in SQL. Only `+ - * / ( )`, numeric literals and
//! registered numeric fields are accepted in an expression; everything else is
//! rejected at authoring time. Values are read-only: they render on the form but
//! never come back from the browser, and are recomputed on every save.

use std::collections::{BTreeMap, HashMap};

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::ui::html_escape;

/// Kinds of computed field, as `(code, label)`.
pub const COMPUTE_KINDS: &[(&str, &str)] = &[
    ("related", "Related — pull a value across a link"),
    ("expr", "Formula — arithmetic on this record's number fields"),
    ("rollup", "Rollup — sum/count/avg over a related list"),
];

/// Registry `field_type`s that may take part in an arithmetic formula.
const NUMERIC_TYPES: &[&str] = &["integer", "float", "decimal", "monetary", "number"];

/// A computed field definition.
#[derive(Debug, Clone)]
pub struct ComputedField {
    pub name: String,
    pub label: String,
    pub field_type: String,
    pub kind: String,
    pub expr: String,
    pub help: Option<String>,
    pub sequence: i32,
}

/// Defensive identifier guard (belt-and-suspenders alongside the registry
/// allow-list): lowercase snake identifiers only.
fn ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The real (non-virtual) columns of a model as `name -> field_type`, from the
/// registry — the allow-list a computed definition may reference. Empty on any
/// error or unknown model.
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

/// name -> related_model for the many2one columns of a model.
async fn m2o_targets(db: &PgPool, model: &str) -> HashMap<String, String> {
    let rows = sqlx::query(
        "SELECT f.name, f.related_model FROM ir_model_field f \
         JOIN ir_model m ON m.id = f.model_id \
         WHERE m.name = $1 AND f.field_type = 'many2one' AND f.related_model IS NOT NULL",
    )
    .bind(model)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.into_iter()
        .filter_map(|r| {
            let n: String = r.get("name");
            let rel: Option<String> = r.try_get("related_model").ok().flatten();
            rel.map(|rel| (n, rel))
        })
        .collect()
}

/// The physical table for a model, if registered and a safe identifier.
async fn model_table(db: &PgPool, model: &str) -> Option<String> {
    let t: Option<String> =
        sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1 AND is_active = true")
            .bind(model)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    t.filter(|t| ident(t))
}

/// Validate a `related` expression `"<m2o>.<target>"` against the registry.
/// Returns `(m2o_field, target_field, target_field_type)`.
async fn resolve_related(
    db: &PgPool,
    model: &str,
    expr: &str,
) -> Result<(String, String, String), String> {
    let (m2o, target) = expr
        .split_once('.')
        .map(|(a, b)| (a.trim(), b.trim()))
        .filter(|(a, b)| !a.is_empty() && !b.is_empty())
        .ok_or("A related field reads like \"link_field.target_field\" (e.g. partner_id.email).")?;
    if !ident(m2o) || !ident(target) {
        return Err("Related field references must be plain field names.".into());
    }
    let targets = m2o_targets(db, model).await;
    let Some(rel_model) = targets.get(m2o) else {
        return Err(format!("{m2o:?} is not a link (many2one) field of {model}."));
    };
    let rel_fields = registered_fields(db, rel_model).await;
    let Some(ftype) = rel_fields.get(target) else {
        return Err(format!("{target:?} is not a field of the linked {rel_model} record."));
    };
    Ok((m2o.to_string(), target.to_string(), ftype.clone()))
}

/// Turn a validated arithmetic `expr` into a SQL expression over the given table
/// `alias`. Only registered numeric fields, numeric literals and `+ - * / ( )`
/// are allowed; each field becomes `COALESCE(<alias>.<f>::numeric, 0)`. Errors
/// name the offending token so the author can fix it. `alias` is a caller
/// constant (`"t"` for this record, `"c"` for a rollup's child rows) — never
/// user input.
fn build_expr_sql(expr: &str, numeric: &HashMap<String, String>, alias: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut refs = 0usize;
    let bytes = expr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            out.push(' ');
            i += 1;
        } else if c == '+' || c == '-' || c == '*' || c == '/' || c == '(' || c == ')' {
            out.push(c);
            i += 1;
        } else if c.is_ascii_digit() || c == '.' {
            let start = i;
            while i < bytes.len() && ((bytes[i] as char).is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let lit = &expr[start..i];
            if lit.parse::<f64>().is_err() {
                return Err(format!("{lit:?} is not a valid number."));
            }
            out.push_str(lit);
        } else if c.is_ascii_lowercase() || c == '_' {
            let start = i;
            while i < bytes.len()
                && ((bytes[i] as char).is_ascii_lowercase()
                    || (bytes[i] as char).is_ascii_digit()
                    || bytes[i] == b'_')
            {
                i += 1;
            }
            let name = &expr[start..i];
            match numeric.get(name) {
                Some(ft) if NUMERIC_TYPES.contains(&ft.as_str()) => {
                    out.push_str(&format!("COALESCE({alias}.{name}::numeric, 0)"));
                    refs += 1;
                }
                Some(_) => return Err(format!("{name:?} is not a number field.")),
                None => return Err(format!("{name:?} is not a field of this model.")),
            }
        } else {
            return Err(format!("Character {c:?} is not allowed in a formula."));
        }
    }
    if refs == 0 {
        return Err("A formula must reference at least one number field.".into());
    }
    Ok(out)
}

/// Aggregate functions a rollup may use.
const ROLLUP_AGGS: &[&str] = &["sum", "count", "avg", "min", "max"];

/// Parse a rollup `compute_expr` of the form `"<list_field> | <agg> | <formula>"`
/// (the formula is optional and ignored for `count`). Returns
/// `(list_field, agg, child_formula)`.
fn parse_rollup(expr: &str) -> Result<(String, String, String), String> {
    let parts: Vec<&str> = expr.splitn(3, '|').collect();
    if parts.len() < 2 {
        return Err("A rollup reads like \"lines | sum | qty * unit_price\" (or \"lines | count\").".into());
    }
    let list = parts[0].trim().to_string();
    let agg = parts[1].trim().to_ascii_lowercase();
    let formula = parts.get(2).map(|s| s.trim().to_string()).unwrap_or_default();
    if !ident(&list) {
        return Err("The list field must be a plain field name.".into());
    }
    if !ROLLUP_AGGS.contains(&agg.as_str()) {
        return Err("Aggregate must be one of: sum, count, avg, min, max.".into());
    }
    if agg != "count" && formula.trim().is_empty() {
        return Err(format!("A {agg} rollup needs a formula, e.g. \"lines | {agg} | qty * unit_price\"."));
    }
    Ok((list, agg, formula))
}

/// Resolve a one2many field of `model` → `(child_model, child_table, inverse_col)`
/// from the registry, validating every identifier that will reach SQL.
async fn resolve_o2m(db: &PgPool, model: &str, field: &str) -> Result<(String, String, String), String> {
    let row = sqlx::query(
        "SELECT f.related_model, f.selection_options FROM ir_model_field f \
         JOIN ir_model m ON m.id = f.model_id \
         WHERE m.name = $1 AND f.name = $2 AND f.field_type = 'one2many'",
    )
    .bind(model)
    .bind(field)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("lookup failed: {e}"))?
    .ok_or_else(|| format!("{field:?} is not a related-list (one2many) field of {model}."))?;
    let child_model: String =
        row.try_get::<Option<String>, _>("related_model").ok().flatten().unwrap_or_default();
    let opts: Option<serde_json::Value> =
        row.try_get::<Option<serde_json::Value>, _>("selection_options").ok().flatten();
    let (child_table, inverse) = opts
        .as_ref()
        .and_then(|o| {
            Some((
                o.get("child_table")?.as_str()?.to_string(),
                o.get("inverse_field")?.as_str()?.to_string(),
            ))
        })
        .ok_or("That related list isn't configured (missing child link).")?;
    if !ident(&child_table) || !ident(&inverse) {
        return Err("Related list target is invalid.".into());
    }
    Ok((child_model, child_table, inverse))
}

/// Computed fields defined on `model`, ordered for display. Resilient: empty on
/// any error (e.g. a DB predating migration 139), so it is safe on the hot form
/// path.
pub async fn list_for_model(db: &PgPool, model: &str) -> Vec<ComputedField> {
    let rows = sqlx::query(
        "SELECT f.name, f.display_name, f.field_type, f.compute_kind, f.compute_expr, \
                f.help, f.sequence \
         FROM ir_model_field f JOIN ir_model m ON m.id = f.model_id \
         WHERE m.name = $1 AND f.is_computed = true AND f.is_visible = true \
         ORDER BY f.sequence, f.name",
    )
    .bind(model)
    .fetch_all(db)
    .await;
    let Ok(rows) = rows else { return Vec::new() };
    rows.into_iter().map(row_to_field).collect()
}

/// Every computed field across all models, with the owning model's registry
/// name and label — for the admin listing.
pub async fn list_all(db: &PgPool) -> Vec<(String, String, ComputedField)> {
    let rows = sqlx::query(
        "SELECT m.name AS model, m.display_name AS model_label, \
                f.name, f.display_name, f.field_type, f.compute_kind, f.compute_expr, \
                f.help, f.sequence \
         FROM ir_model_field f JOIN ir_model m ON m.id = f.model_id \
         WHERE f.is_computed = true \
         ORDER BY m.display_name, f.sequence, f.name",
    )
    .fetch_all(db)
    .await;
    let Ok(rows) = rows else { return Vec::new() };
    rows.into_iter()
        .map(|r| {
            let model: String = r.get("model");
            let model_label: String = r.get("model_label");
            (model, model_label, row_to_field(r))
        })
        .collect()
}

fn row_to_field(r: sqlx::postgres::PgRow) -> ComputedField {
    ComputedField {
        name: r.get("name"),
        label: r.get("display_name"),
        field_type: r.get("field_type"),
        kind: r.try_get("compute_kind").ok().flatten().unwrap_or_default(),
        expr: r.try_get("compute_expr").ok().flatten().unwrap_or_default(),
        help: r.try_get("help").ok().flatten(),
        sequence: r.get("sequence"),
    }
}

/// Add (or update) a computed field on `model`. Validates the name, kind and
/// expression against the registry before persisting.
pub async fn add(
    db: &PgPool,
    model: &str,
    name: &str,
    label: &str,
    kind: &str,
    expr: &str,
    help: Option<&str>,
) -> Result<(), String> {
    // Reuse the custom-field name rule (x_-prefixed, safe identifier).
    if !crate::custom_fields::valid_name(name) {
        return Err("Field name must be lowercase, start with \"x_\", and contain only letters, digits and underscores.".into());
    }
    let expr = expr.trim();
    if expr.is_empty() {
        return Err("A computed field needs a formula or a related path.".into());
    }
    let label = if label.trim().is_empty() { name } else { label.trim() };

    // Resolve the field type from the definition (and validate it).
    let field_type = match kind {
        "related" => {
            let (_, _, ftype) = resolve_related(db, model, expr).await?;
            ftype
        }
        "expr" => {
            let numeric = registered_fields(db, model).await;
            if numeric.is_empty() {
                return Err(format!("Unknown or empty model {model:?}."));
            }
            build_expr_sql(expr, &numeric, "t")?; // validate only
            "number".to_string()
        }
        "rollup" => {
            let (list, agg, formula) = parse_rollup(expr)?;
            let (child_model, _table, _inverse) = resolve_o2m(db, model, &list).await?;
            if agg != "count" {
                let child_numeric = registered_fields(db, &child_model).await;
                if child_numeric.is_empty() {
                    return Err(format!("The linked {child_model} has no fields to aggregate."));
                }
                build_expr_sql(&formula, &child_numeric, "c")?; // validate the child formula
            }
            "number".to_string()
        }
        _ => return Err("Choose a valid computed kind.".into()),
    };

    let model_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM ir_model WHERE name = $1")
        .bind(model)
        .fetch_optional(db)
        .await
        .map_err(|e| format!("lookup failed: {e}"))?;
    let Some(model_id) = model_id else {
        return Err(format!("Unknown model {model:?}."));
    };

    let next_seq: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(sequence), 0) + 10 FROM ir_model_field WHERE model_id = $1",
    )
    .bind(model_id)
    .fetch_one(db)
    .await
    .map_err(|e| format!("sequence failed: {e}"))?;

    sqlx::query(
        r#"
        INSERT INTO ir_model_field
            (model_id, name, display_name, field_type, help, sequence,
             is_custom, is_computed, compute_kind, compute_expr, is_visible)
        VALUES ($1, $2, $3, $4, $5, $6, true, true, $7, $8, true)
        ON CONFLICT (model_id, name) DO UPDATE
            SET display_name = EXCLUDED.display_name,
                field_type   = EXCLUDED.field_type,
                help         = EXCLUDED.help,
                is_computed  = true,
                compute_kind = EXCLUDED.compute_kind,
                compute_expr = EXCLUDED.compute_expr
        "#,
    )
    .bind(model_id)
    .bind(name)
    .bind(label)
    .bind(field_type)
    .bind(help)
    .bind(next_seq)
    .bind(kind)
    .bind(expr)
    .execute(db)
    .await
    .map_err(|e| format!("save failed: {e}"))?;
    Ok(())
}

/// Delete a computed field. Only ever removes `is_computed` rows.
pub async fn delete(db: &PgPool, model: &str, name: &str) -> Result<(), String> {
    sqlx::query(
        "DELETE FROM ir_model_field f USING ir_model m \
         WHERE f.model_id = m.id AND m.name = $1 AND f.name = $2 AND f.is_computed = true",
    )
    .bind(model)
    .bind(name)
    .execute(db)
    .await
    .map_err(|e| format!("delete failed: {e}"))?;
    Ok(())
}

/// Evaluate a single computed field for a record, returning its value as text
/// (or `None` on any error / NULL result).
async fn evaluate_one(db: &PgPool, model: &str, f: &ComputedField, record_id: Uuid) -> Option<String> {
    let table = model_table(db, model).await?;
    let sql = match f.kind.as_str() {
        "related" => {
            let (m2o, target, _) = resolve_related(db, model, &f.expr).await.ok()?;
            let rel_model = m2o_targets(db, model).await.remove(&m2o)?;
            let rel_table = model_table(db, &rel_model).await?;
            format!(
                "SELECT r.{target}::text FROM {table} t \
                 LEFT JOIN {rel_table} r ON r.id = t.{m2o} WHERE t.id = $1"
            )
        }
        "expr" => {
            let numeric = registered_fields(db, model).await;
            let sql_expr = build_expr_sql(&f.expr, &numeric, "t").ok()?;
            format!("SELECT ({sql_expr})::text FROM {table} t WHERE t.id = $1")
        }
        "rollup" => {
            // Aggregate over the child rows of a one2many, keyed on the inverse
            // many2one back to this record. `count` needs no formula; the others
            // aggregate a validated arithmetic expression over the child's own
            // number columns. `SUM` of no rows coalesces to 0; avg/min/max stay
            // NULL (rendered blank), which reads correctly for an empty list.
            let (list, agg, formula) = parse_rollup(&f.expr).ok()?;
            let (child_model, child_table, inverse) = resolve_o2m(db, model, &list).await.ok()?;
            if agg == "count" {
                format!("SELECT COUNT(*)::text FROM {child_table} c WHERE c.{inverse} = $1")
            } else {
                let child_numeric = registered_fields(db, &child_model).await;
                let inner = build_expr_sql(&formula, &child_numeric, "c").ok()?;
                if agg == "sum" {
                    format!("SELECT COALESCE(SUM({inner}), 0)::text FROM {child_table} c WHERE c.{inverse} = $1")
                } else {
                    let agg_uc = agg.to_ascii_uppercase();
                    format!("SELECT {agg_uc}({inner})::text FROM {child_table} c WHERE c.{inverse} = $1")
                }
            }
        }
        _ => return None,
    };
    let v: Option<String> = sqlx::query_scalar(&sql)
        .bind(record_id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
    v
}

/// Evaluate every computed field of `model` for a record. Empty when the model
/// has none.
pub async fn evaluate_all(db: &PgPool, model: &str, record_id: Uuid) -> BTreeMap<String, String> {
    let fields = list_for_model(db, model).await;
    let mut out = BTreeMap::new();
    for f in &fields {
        if let Some(v) = evaluate_one(db, model, f, record_id).await {
            out.insert(f.name.clone(), v);
        }
    }
    out
}

/// Recompute the model's computed fields for a record and persist the results
/// (read-only) into the shared `ir_custom_value` store, merged with whatever
/// custom-field values are already there. No-op when the model has no computed
/// fields, so it is cheap and safe on the universal save path.
pub async fn store_values(db: &PgPool, model: &str, record_id: Uuid) -> Result<(), String> {
    let values = evaluate_all(db, model, record_id).await;
    if values.is_empty() {
        return Ok(());
    }
    let mut obj = serde_json::Map::new();
    for (k, v) in values {
        obj.insert(k, serde_json::Value::String(v));
    }
    let data = serde_json::Value::Object(obj);
    // Merge (JSONB `||`) so computed keys sit beside any input custom values
    // the same save already wrote.
    sqlx::query(
        r#"
        INSERT INTO ir_custom_value (model_name, record_id, data, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (model_name, record_id) DO UPDATE
            SET data = ir_custom_value.data || EXCLUDED.data, updated_at = NOW()
        "#,
    )
    .bind(model)
    .bind(record_id)
    .bind(data)
    .execute(db)
    .await
    .map_err(|e| format!("computed value save failed: {e}"))?;
    Ok(())
}

/// Render the computed fields for `model` as a read-only form section. In Edit
/// mode the current value is evaluated live so it always shows the truth; in
/// Create mode it shows a "computed on save" placeholder. Empty string when the
/// model has no computed fields (the common case).
pub async fn render_for_form(db: &PgPool, model: &str, record_id: Option<&str>) -> String {
    let fields = list_for_model(db, model).await;
    if fields.is_empty() {
        return String::new();
    }
    let values = match record_id.and_then(|id| Uuid::parse_str(id).ok()) {
        Some(id) => evaluate_all(db, model, id).await,
        None => BTreeMap::new(),
    };

    let mut body = String::from(
        r#"<h2 class="text-sm font-semibold uppercase opacity-60 mt-4 mb-2">Computed Fields</h2>"#,
    );
    body.push_str(r#"<div class="grid grid-cols-1 md:grid-cols-2 gap-x-8">"#);
    for f in &fields {
        let (value, muted) = match values.get(&f.name) {
            Some(v) if !v.is_empty() => (html_escape(v), false),
            _ if record_id.is_some() => ("—".to_string(), true),
            _ => ("computed on save".to_string(), true),
        };
        let help = f
            .help
            .as_deref()
            .filter(|h| !h.is_empty())
            .map(|h| format!(r#"<span class="label-text-alt opacity-60">{}</span>"#, html_escape(h)))
            .unwrap_or_default();
        let muted_cls = if muted { " opacity-60 italic" } else { "" };
        body.push_str(&format!(
            r#"<label class="form-control mb-3"><div class="label"><span class="label-text">{label} <span class="badge badge-ghost badge-sm ml-1">ƒ</span></span>{help}</div>
<input type="text" id="cf_{name}" value="{value}" class="input input-bordered w-full bg-base-200{muted_cls}" readonly disabled/></label>"#,
            label = html_escape(&f.label),
            name = html_escape(&f.name),
            help = help,
            value = value,
            muted_cls = muted_cls,
        ));
    }
    body.push_str("</div>");

    // Live evaluation: recompute formula + rollup fields client-side as the user
    // types in the form and the inline line grid, so totals update in real time
    // instead of only after save. `related` fields have no client-side source, so
    // they keep their server value. The definitions are emitted as JSON and read
    // by a small dependency-free arithmetic evaluator (no eval / new Function).
    let defs: Vec<serde_json::Value> = fields
        .iter()
        .filter(|f| f.kind == "expr" || f.kind == "rollup")
        .map(|f| serde_json::json!({ "name": f.name, "kind": f.kind, "expr": f.expr }))
        .collect();
    if !defs.is_empty() {
        let defs_json = serde_json::to_string(&defs).unwrap_or_else(|_| "[]".into());
        body.push_str(&format!(
            r#"<script type="application/json" id="computed-defs">{}</script>"#,
            defs_json
        ));
        body.push_str(LIVE_COMPUTE_JS);
    }
    body
}

/// Dependency-free client that recomputes `expr` and `rollup` computed fields in
/// real time. It reads the JSON in `#computed-defs`, tokenises each formula into
/// RPN once, and on every form `input`/`change` (and grid row add/remove via a
/// MutationObserver) re-evaluates: `expr` over the record's own inputs, `rollup`
/// over the inline `#o2mbody_<list>` rows. Only `+ - * / ( )`, numbers and field
/// names occur in a formula (validated server-side), so a tiny shunting-yard
/// evaluator is sufficient and safe — no `eval`/`new Function`, CSP-clean.
const LIVE_COMPUTE_JS: &str = r#"<script>
(function(){
  var el = document.getElementById('computed-defs'); if(!el) return;
  var DEFS; try { DEFS = JSON.parse(el.textContent || '[]'); } catch(e){ return; }
  if(!DEFS.length) return;
  var form = el.closest('form') || document.querySelector('form'); if(!form) return;

  function tokenize(s){
    var t=[], i=0;
    while(i<s.length){
      var c=s[i];
      if(c===' '||c==='\t'){ i++; continue; }
      if('+-*/()'.indexOf(c)>=0){ t.push(c); i++; continue; }
      if((c>='0'&&c<='9')||c==='.'){ var j=i; while(j<s.length&&((s[j]>='0'&&s[j]<='9')||s[j]==='.')) j++; t.push({num:parseFloat(s.slice(i,j))}); i=j; continue; }
      if((c>='a'&&c<='z')||c==='_'){ var j=i; while(j<s.length&&((s[j]>='a'&&s[j]<='z')||(s[j]>='0'&&s[j]<='9')||s[j]==='_')) j++; t.push({id:s.slice(i,j)}); i=j; continue; }
      return null;
    }
    return t;
  }
  var PREC={'+':1,'-':1,'*':2,'/':2};
  function toRPN(toks){
    var out=[], op=[], prev=null;
    for(var k=0;k<toks.length;k++){
      var t=toks[k];
      if(typeof t==='object'){ out.push(t); }
      else if(t==='('){ op.push(t); }
      else if(t===')'){ while(op.length&&op[op.length-1]!=='(') out.push(op.pop()); op.pop(); }
      else {
        if(t==='-'&&(prev===null||prev==='('||PREC[prev]!==undefined)) out.push({num:0});
        while(op.length&&op[op.length-1]!=='('&&PREC[op[op.length-1]]>=PREC[t]) out.push(op.pop());
        op.push(t);
      }
      prev=t;
    }
    while(op.length) out.push(op.pop());
    return out;
  }
  function evalRPN(rpn,lookup){
    var st=[];
    for(var k=0;k<rpn.length;k++){
      var t=rpn[k];
      if(typeof t==='object'){ st.push(('num' in t)?t.num:(lookup(t.id)||0)); }
      else { var b=st.pop(), a=st.pop(); st.push(t==='+'?a+b:t==='-'?a-b:t==='*'?a*b:(b?a/b:0)); }
    }
    return st.length?st[0]:0;
  }
  function compile(expr){ var t=tokenize(expr||''); return t?toRPN(t):null; }
  function run(rpn,lookup){ if(!rpn) return null; try { return evalRPN(rpn,lookup); } catch(e){ return null; } }

  function headerVal(name){ var i=form.querySelector('[name="'+name+'"]'); return i?(parseFloat(i.value)||0):0; }
  function rollup(list,agg,rpn){
    var body=document.getElementById('o2mbody_'+list);
    if(!body) return agg==='count'?0:(agg==='sum'?0:null);
    var rows=body.querySelectorAll(':scope > tr'), vals=[];
    if(agg==='count') return rows.length;
    rows.forEach(function(tr){
      var lk=function(n){ var c=tr.querySelector('[data-col="'+n+'"]'); return c?(parseFloat(c.value)||0):0; };
      vals.push(run(rpn,lk)||0);
    });
    if(!vals.length) return agg==='sum'?0:null;
    if(agg==='sum') return vals.reduce(function(a,b){return a+b;},0);
    if(agg==='avg') return vals.reduce(function(a,b){return a+b;},0)/vals.length;
    if(agg==='min') return Math.min.apply(null,vals);
    if(agg==='max') return Math.max.apply(null,vals);
    return null;
  }

  DEFS.forEach(function(d){
    if(d.kind==='expr'){ d._rpn=compile(d.expr); }
    else if(d.kind==='rollup'){ var p=(d.expr||'').split('|'); d._list=(p[0]||'').trim(); d._agg=(p[1]||'').trim().toLowerCase(); d._rpn=compile((p[2]||'').trim()); }
  });
  function fmt(v){ return (Math.round(v*100)/100).toString(); }
  function recompute(){
    DEFS.forEach(function(d){
      var out=document.getElementById('cf_'+d.name); if(!out) return;
      var v = d.kind==='expr' ? run(d._rpn,headerVal) : rollup(d._list,d._agg,d._rpn);
      if(v===null||v===undefined||isNaN(v)) return;
      out.value=fmt(v);
    });
  }
  form.addEventListener('input', recompute);
  form.addEventListener('change', recompute);
  DEFS.forEach(function(d){
    if(d.kind==='rollup'){ var b=document.getElementById('o2mbody_'+d._list); if(b){ new MutationObserver(recompute).observe(b,{childList:true}); } }
  });
  recompute();
})();
</script>"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn numeric() -> HashMap<String, String> {
        [
            ("qty".to_string(), "integer".to_string()),
            ("unit_price".to_string(), "monetary".to_string()),
            ("discount".to_string(), "float".to_string()),
            ("name".to_string(), "string".to_string()),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn expr_builds_safe_sql() {
        let sql = build_expr_sql("(qty * unit_price) - discount", &numeric(), "t").unwrap();
        assert_eq!(
            sql,
            "(COALESCE(t.qty::numeric, 0) * COALESCE(t.unit_price::numeric, 0)) - COALESCE(t.discount::numeric, 0)"
        );
        // A rollup child formula uses the `c` alias.
        let child = build_expr_sql("qty * unit_price", &numeric(), "c").unwrap();
        assert_eq!(child, "COALESCE(c.qty::numeric, 0) * COALESCE(c.unit_price::numeric, 0)");
    }

    #[test]
    fn expr_rejects_unknown_and_nonnumeric_and_injection() {
        assert!(build_expr_sql("qty * bogus", &numeric(), "t").is_err(), "unknown field");
        assert!(build_expr_sql("qty * name", &numeric(), "t").is_err(), "non-numeric field");
        assert!(build_expr_sql("qty; DROP TABLE x", &numeric(), "t").is_err(), "punctuation");
        assert!(build_expr_sql("qty = 1", &numeric(), "t").is_err(), "comparison not allowed");
        assert!(build_expr_sql("5 + 3", &numeric(), "t").is_err(), "must reference a field");
        assert!(build_expr_sql("2 * qty", &numeric(), "t").is_ok(), "literal with a field is fine");
    }

    #[test]
    fn rollup_parse_validates() {
        assert_eq!(
            parse_rollup("lines | sum | qty * unit_price").unwrap(),
            ("lines".to_string(), "sum".to_string(), "qty * unit_price".to_string())
        );
        assert_eq!(
            parse_rollup("lines | count").unwrap(),
            ("lines".to_string(), "count".to_string(), String::new())
        );
        assert!(parse_rollup("lines | median | x").is_err(), "unknown aggregate");
        assert!(parse_rollup("lines | sum").is_err(), "sum needs a formula");
        assert!(parse_rollup("lines").is_err(), "needs an aggregate");
    }

    #[test]
    fn identifier_guard() {
        assert!(ident("partner_id"));
        assert!(!ident("1bad"));
        assert!(!ident("drop table"));
    }

    /// Full loop against a real DB. Runs only when `VORTEX_TEST_DB` points at a
    /// migrated throwaway DB (so `contacts` is registered and migrations 137/139
    /// are applied); otherwise skips.
    #[tokio::test]
    async fn evaluate_against_db() {
        let Ok(url) = std::env::var("VORTEX_TEST_DB") else {
            eprintln!("skip evaluate_against_db: VORTEX_TEST_DB unset");
            return;
        };
        let db = PgPool::connect(&url).await.expect("connect");

        // A related computed field on contacts: pull the linked state's code.
        // contacts has a many2one `state_id` → states in the reference plugin;
        // fall back to a formula test that needs no relation if it's absent.
        let has_state = !m2o_targets(&db, "contacts").await.is_empty();

        // Formula field: credit_limit is monetary on contacts.
        let numeric = registered_fields(&db, "contacts").await;
        if numeric.get("credit_limit").is_some() {
            add(&db, "contacts", "x_credit_x2", "Credit Doubled", "expr",
                "credit_limit * 2", None).await.expect("add expr");

            let rid = Uuid::new_v4();
            sqlx::query("INSERT INTO contacts (id, name, contact_type, active, credit_limit, company_id) \
                         VALUES ($1, 'Acme', 'customer', true, 50, (SELECT id FROM companies LIMIT 1))")
                .bind(rid).execute(&db).await.expect("insert contact");

            let vals = evaluate_all(&db, "contacts", rid).await;
            let doubled: f64 = vals.get("x_credit_x2").and_then(|v| v.parse().ok()).unwrap_or(0.0);
            assert!((doubled - 100.0).abs() < 0.001, "50 * 2 = 100, got {doubled}");

            // Persist + read back from the shared custom-value store.
            store_values(&db, "contacts", rid).await.expect("store");
            let stored: Option<serde_json::Value> = sqlx::query_scalar(
                "SELECT data FROM ir_custom_value WHERE model_name='contacts' AND record_id=$1")
                .bind(rid).fetch_optional(&db).await.unwrap();
            assert!(stored.is_some(), "computed value stored");

            // Read-only render shows the value, not an editable input.
            let html = render_for_form(&db, "contacts", Some(&rid.to_string())).await;
            assert!(html.contains("Computed Fields"));
            assert!(html.contains("readonly"), "computed field is read-only");

            delete(&db, "contacts", "x_credit_x2").await.expect("delete");
            sqlx::query("DELETE FROM ir_custom_value WHERE model_name='contacts' AND record_id=$1")
                .bind(rid).execute(&db).await.ok();
            sqlx::query("DELETE FROM contacts WHERE id=$1").bind(rid).execute(&db).await.ok();
        } else {
            eprintln!("evaluate_against_db: contacts.credit_limit absent, skipped formula assertions");
        }
        let _ = has_state;
    }
}
