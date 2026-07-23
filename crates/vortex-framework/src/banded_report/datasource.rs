//! Dataset access for banded reports.
//!
//! Mirrors the safe-SQL discipline of [`crate::user_reports`]: every dynamic
//! identifier is allow-listed with [`ident`] *and* checked against the model's
//! registered fields (`ir_model` / `ir_model_field`); filter values are always
//! bound. Many2one fields resolve to the related record's `name` via a
//! correlated subquery so reports show labels, not raw ids.

use crate::banded_report::model::{Dataset, SortKey};
use sqlx::{PgPool, Row};
use std::collections::BTreeMap;

fn ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn valid_operator(op: &str) -> bool {
    matches!(op, "=" | "!=" | "ilike" | ">" | "<" | ">=" | "<=")
}

/// A single run-time filter (built from `ir_report_filter`).
#[derive(Debug, Clone)]
pub struct Filter {
    pub field: String,
    pub operator: String,
    pub value: Option<String>,
}

async fn model_table(db: &PgPool, model_name: &str) -> Option<String> {
    sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1 AND is_active = true")
        .bind(model_name)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

/// field name -> (field_type, related_model).
async fn model_fields(db: &PgPool, model_name: &str) -> BTreeMap<String, (String, Option<String>)> {
    let rows = sqlx::query(
        "SELECT f.name, f.field_type, f.related_model FROM ir_model_field f \
         JOIN ir_model m ON m.id = f.model_id WHERE m.name = $1",
    )
    .bind(model_name)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.iter()
        .map(|r| {
            (
                r.get::<String, _>("name"),
                (r.get::<String, _>("field_type"), r.try_get::<Option<String>, _>("related_model").ok().flatten()),
            )
        })
        .collect()
}

/// Fetch dataset rows as field->text maps. Errors carry a human message; the
/// caller renders it in the report body rather than 500-ing.
pub async fn fetch(
    db: &PgPool,
    model_name: &str,
    dataset: &Dataset,
    filters: &[Filter],
    row_limit: i32,
) -> Result<Vec<BTreeMap<String, String>>, String> {
    if model_name.is_empty() {
        return Ok(Vec::new()); // static / no-data report
    }
    let table = model_table(db, model_name).await.ok_or_else(|| format!("unknown model '{model_name}'"))?;
    if !ident(&table) {
        return Err("invalid model table".into());
    }
    let fields = model_fields(db, model_name).await;
    let names: Vec<String> = fields.keys().filter(|n| ident(n)).cloned().collect();
    if names.is_empty() {
        return Err("model has no registered fields".into());
    }

    // SELECT list: each field cast to text; many2one resolved to related name.
    let mut select_parts: Vec<String> = Vec::new();
    for n in &names {
        match fields.get(n) {
            Some((ftype, Some(rel))) if ftype == "many2one" => {
                if let Some(rtable) = model_table(db, rel).await {
                    if ident(&rtable) {
                        select_parts.push(format!(
                            "(SELECT r.name FROM {rtable} r WHERE r.id = t.{n})::text AS {n}"
                        ));
                        continue;
                    }
                }
                select_parts.push(format!("t.{n}::text AS {n}"));
            }
            _ => select_parts.push(format!("t.{n}::text AS {n}")),
        }
    }
    let select = select_parts.join(", ");

    // WHERE from bound filters.
    let mut where_parts: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    for f in filters {
        if !ident(&f.field) || !fields.contains_key(&f.field) || !valid_operator(&f.operator) {
            return Err(format!("invalid filter on '{}'", f.field));
        }
        let idx = binds.len() + 1;
        where_parts.push(format!("t.{}::text {} ${}", f.field, f.operator, idx));
        let raw = f.value.clone().unwrap_or_default();
        binds.push(if f.operator == "ilike" { format!("%{raw}%") } else { raw });
    }
    let where_sql = if where_parts.is_empty() { String::new() } else { format!(" WHERE {}", where_parts.join(" AND ")) };

    // ORDER BY from the layout's sort keys (validated).
    let mut order_parts: Vec<String> = Vec::new();
    for s in sort_or_group(dataset) {
        if ident(&s.field) && fields.contains_key(&s.field) {
            let dir = if s.dir.eq_ignore_ascii_case("desc") { "DESC" } else { "ASC" };
            order_parts.push(format!("t.{} {}", s.field, dir));
        }
    }
    let order_sql = if order_parts.is_empty() { String::new() } else { format!(" ORDER BY {}", order_parts.join(", ")) };

    let limit = row_limit.clamp(1, 200_000);
    let sql = format!("SELECT {select} FROM {table} t{where_sql}{order_sql} LIMIT {limit}");

    let mut q = sqlx::query(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let rows = q.fetch_all(db).await.map_err(|e| format!("query failed: {e}"))?;
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        let mut map = BTreeMap::new();
        for n in &names {
            let v: Option<String> = row.try_get(n.as_str()).ok().flatten();
            map.insert(n.clone(), v.unwrap_or_default());
        }
        out.push(map);
    }
    Ok(out)
}

/// Sort keys to apply. Group columns are prepended so grouping is stable even
/// when the author forgets to add an explicit sort on the group field.
fn sort_or_group(dataset: &Dataset) -> Vec<SortKey> {
    let mut keys: Vec<SortKey> = Vec::new();
    for g in &dataset.groups {
        // A group expr of the bare form `$F{field}` implies an ORDER BY field.
        if let Some(field) = bare_field(&g.expr) {
            if !keys.iter().any(|k| k.field == field) {
                keys.push(SortKey { field, dir: "asc".into() });
            }
        }
    }
    for s in &dataset.sort {
        if !keys.iter().any(|k| k.field == s.field) {
            keys.push(s.clone());
        }
    }
    keys
}

/// If `expr` is exactly `$F{name}`, return `name`. Used to auto-order by group.
fn bare_field(expr: &str) -> Option<String> {
    let e = expr.trim();
    let inner = e.strip_prefix("$F{")?.strip_suffix('}')?;
    let inner = inner.trim();
    if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Some(inner.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banded_report::model::Group;

    #[test]
    fn bare_field_extraction() {
        assert_eq!(bare_field("$F{partner}"), Some("partner".into()));
        assert_eq!(bare_field("  $F{ partner } "), Some("partner".into()));
        assert_eq!(bare_field("$F{a} + $F{b}"), None);
        assert_eq!(bare_field("upper($F{x})"), None);
    }

    #[test]
    fn group_field_is_prepended_to_sort() {
        let ds = Dataset {
            model: "m".into(),
            sort: vec![SortKey { field: "date".into(), dir: "desc".into() }],
            groups: vec![Group { expr: "$F{partner}".into(), header: "g".into(), footer: String::new(), reprint: false }],
        };
        let keys = sort_or_group(&ds);
        assert_eq!(keys[0].field, "partner");
        assert_eq!(keys[1].field, "date");
    }
}
