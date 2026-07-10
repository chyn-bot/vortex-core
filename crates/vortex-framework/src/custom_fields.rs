//! Per-tenant custom fields (Initiative #2).
//!
//! A custom field is a row in `ir_model_field` with `is_custom = true` on a
//! model that already exists in the registry (which, since Initiative #1, is
//! derived from `#[derive(Model)]`). Its values live in the central
//! `ir_custom_value` overflow store — one JSONB blob per record — so a tenant
//! admin can add a field to any model at runtime with **no runtime DDL** on the
//! model's own table.
//!
//! The generic form framework calls [`render_for_form`] and [`save_values`]
//! automatically, so a custom field appears on, and persists from, every
//! `FormConfig`-driven form with no per-page code.
//!
//! Scope of this first cut: `is_visible` gates rendering; group-based field
//! ACL and value-change audit ride on top later. The derive registry sync only
//! upserts code-declared fields and never deletes, so custom rows are safe
//! beside them.

use std::collections::BTreeMap;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::ui::html_escape;

/// Field types an admin may choose for a custom field — a safe subset of the
/// `ir_model_field` vocabulary (no relational types in this first cut).
pub const CUSTOM_FIELD_TYPES: &[(&str, &str)] = &[
    ("string", "Text (single line)"),
    ("text", "Text (multi-line)"),
    ("number", "Number"),
    ("monetary", "Monetary"),
    ("boolean", "Checkbox"),
    ("date", "Date"),
    ("datetime", "Date & time"),
    ("selection", "Selection"),
];

/// A custom field definition.
#[derive(Debug, Clone)]
pub struct CustomField {
    pub name: String,
    pub label: String,
    pub field_type: String,
    pub selection_options: Vec<String>,
    pub help: Option<String>,
    pub sequence: i32,
    pub is_visible: bool,
}

/// Is `t` an admin-choosable custom field type?
pub fn is_valid_type(t: &str) -> bool {
    CUSTOM_FIELD_TYPES.iter().any(|(k, _)| *k == t)
}

/// Validate a custom field name: must be `x_`-prefixed and a safe identifier.
/// The `x_` convention keeps custom names from ever colliding with a
/// code-declared column.
pub fn valid_name(name: &str) -> bool {
    name.len() >= 3
        && name.len() <= 63
        && name.starts_with("x_")
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && name.bytes().next().is_some_and(|b| b == b'x')
}

/// Custom fields defined on `model`, ordered for display. Resilient: returns
/// empty on any error (e.g. a database that predates migration 137), so it is
/// safe to call from the hot form path unconditionally.
pub async fn list_for_model(db: &PgPool, model: &str) -> Vec<CustomField> {
    let rows = sqlx::query(
        r#"
        SELECT f.name, f.display_name, f.field_type, f.selection_options,
               f.help, f.sequence, f.is_visible
        FROM ir_model_field f
        JOIN ir_model m ON m.id = f.model_id
        WHERE m.name = $1 AND f.is_custom = true AND COALESCE(f.is_computed, false) = false
        ORDER BY f.sequence, f.name
        "#,
    )
    .bind(model)
    .fetch_all(db)
    .await;

    let Ok(rows) = rows else { return Vec::new() };
    rows.into_iter().map(row_to_field).collect()
}

/// Every custom field across all models, with the owning model's registry
/// name and label — for the admin listing.
pub async fn list_all(db: &PgPool) -> Vec<(String, String, CustomField)> {
    let rows = sqlx::query(
        r#"
        SELECT m.name AS model, m.display_name AS model_label,
               f.name, f.display_name, f.field_type, f.selection_options,
               f.help, f.sequence, f.is_visible
        FROM ir_model_field f
        JOIN ir_model m ON m.id = f.model_id
        WHERE f.is_custom = true AND COALESCE(f.is_computed, false) = false
        ORDER BY m.display_name, f.sequence, f.name
        "#,
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

fn row_to_field(r: sqlx::postgres::PgRow) -> CustomField {
    let options: Option<serde_json::Value> = r.try_get("selection_options").ok().flatten();
    let selection_options = match options {
        Some(serde_json::Value::Array(a)) => a
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    CustomField {
        name: r.get("name"),
        label: r.get("display_name"),
        field_type: r.get("field_type"),
        selection_options,
        help: r.try_get("help").ok().flatten(),
        sequence: r.get("sequence"),
        is_visible: r.get("is_visible"),
    }
}

/// Add (or update) a custom field on `model`. Validates the name and type, then
/// upserts an `ir_model_field` row with `is_custom = true`. Errors on a bad
/// name/type or an unknown model.
pub async fn add(
    db: &PgPool,
    model: &str,
    name: &str,
    label: &str,
    field_type: &str,
    selection_options: &[String],
    help: Option<&str>,
) -> Result<(), String> {
    if !valid_name(name) {
        return Err("Field name must be lowercase, start with \"x_\", and contain only letters, digits and underscores.".into());
    }
    if !is_valid_type(field_type) {
        return Err(format!("Unknown field type {field_type:?}."));
    }
    let label = if label.trim().is_empty() { name } else { label.trim() };

    let model_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM ir_model WHERE name = $1")
        .bind(model)
        .fetch_optional(db)
        .await
        .map_err(|e| format!("lookup failed: {e}"))?;
    let Some(model_id) = model_id else {
        return Err(format!("Unknown model {model:?}."));
    };

    let options_json: Option<serde_json::Value> = if field_type == "selection" {
        if selection_options.is_empty() {
            return Err("A selection field needs at least one option.".into());
        }
        Some(serde_json::Value::Array(
            selection_options
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        ))
    } else {
        None
    };

    // Custom fields sort after the code-declared ones.
    let next_seq: i32 =
        sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) + 10 FROM ir_model_field WHERE model_id = $1")
            .bind(model_id)
            .fetch_one(db)
            .await
            .map_err(|e| format!("sequence failed: {e}"))?;

    sqlx::query(
        r#"
        INSERT INTO ir_model_field
            (model_id, name, display_name, field_type, selection_options, help, sequence, is_custom, is_visible)
        VALUES ($1, $2, $3, $4, $5, $6, $7, true, true)
        ON CONFLICT (model_id, name) DO UPDATE
            SET display_name      = EXCLUDED.display_name,
                field_type        = EXCLUDED.field_type,
                selection_options = EXCLUDED.selection_options,
                help              = EXCLUDED.help
        "#,
    )
    .bind(model_id)
    .bind(name)
    .bind(label)
    .bind(field_type)
    .bind(options_json)
    .bind(help)
    .bind(next_seq)
    .execute(db)
    .await
    .map_err(|e| format!("save failed: {e}"))?;

    Ok(())
}

/// Delete a custom field. Only ever removes `is_custom` rows, so a code-declared
/// field can never be dropped through this path.
pub async fn delete(db: &PgPool, model: &str, name: &str) -> Result<(), String> {
    sqlx::query(
        r#"
        DELETE FROM ir_model_field f
        USING ir_model m
        WHERE f.model_id = m.id AND m.name = $1 AND f.name = $2 AND f.is_custom = true
        "#,
    )
    .bind(model)
    .bind(name)
    .execute(db)
    .await
    .map_err(|e| format!("delete failed: {e}"))?;
    Ok(())
}

/// Load a record's custom values as a string map (JSONB blob flattened).
pub async fn load_values(db: &PgPool, model: &str, record_id: Uuid) -> BTreeMap<String, String> {
    let data: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT data FROM ir_custom_value WHERE model_name = $1 AND record_id = $2")
            .bind(model)
            .bind(record_id)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();

    let mut out = BTreeMap::new();
    if let Some(serde_json::Value::Object(map)) = data {
        for (k, v) in map {
            let s = match v {
                serde_json::Value::String(s) => s,
                serde_json::Value::Null => continue,
                other => other.to_string(),
            };
            out.insert(k, s);
        }
    }
    out
}

/// Persist submitted custom values for a record. Extracts the keys that match
/// this model's custom fields from the raw form `pairs`, then upserts the JSONB
/// blob. No-op when the model has no custom fields (so it is cheap and safe on
/// the universal save path). Unchecked booleans (which browsers omit) are
/// stored as `false`.
pub async fn save_values(
    db: &PgPool,
    model: &str,
    record_id: Uuid,
    pairs: &[(String, String)],
) -> Result<(), String> {
    let fields = list_for_model(db, model).await;
    if fields.is_empty() {
        return Ok(());
    }

    let mut obj = serde_json::Map::new();
    for f in &fields {
        // Last value wins (mirrors the core form normalizer).
        let raw = pairs.iter().rev().find(|(k, _)| k == &f.name).map(|(_, v)| v.trim());
        let value = match f.field_type.as_str() {
            "boolean" => Some(if matches!(raw, Some("on") | Some("true")) { "true" } else { "false" }.to_string()),
            _ => raw.map(str::to_string),
        };
        if let Some(v) = value {
            obj.insert(f.name.clone(), serde_json::Value::String(v));
        }
    }

    let data = serde_json::Value::Object(obj);
    sqlx::query(
        r#"
        INSERT INTO ir_custom_value (model_name, record_id, data, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (model_name, record_id) DO UPDATE
            SET data = EXCLUDED.data, updated_at = NOW()
        "#,
    )
    .bind(model)
    .bind(record_id)
    .bind(data)
    .execute(db)
    .await
    .map_err(|e| format!("custom value save failed: {e}"))?;
    Ok(())
}

/// Render the visible custom fields for `model` as a form section, prefilled
/// from the record's stored values in Edit mode. Returns an empty string when
/// the model has no visible custom fields (the common case), so the form path
/// can append it unconditionally.
pub async fn render_for_form(db: &PgPool, model: &str, record_id: Option<&str>) -> String {
    let fields: Vec<CustomField> = list_for_model(db, model)
        .await
        .into_iter()
        .filter(|f| f.is_visible)
        .collect();
    if fields.is_empty() {
        return String::new();
    }

    let values = match record_id.and_then(|id| Uuid::parse_str(id).ok()) {
        Some(id) => load_values(db, model, id).await,
        None => BTreeMap::new(),
    };

    let mut body = String::from(
        r#"<h2 class="text-sm font-semibold uppercase opacity-60 mt-4 mb-2">Custom Fields</h2>"#,
    );
    body.push_str(r#"<div class="grid grid-cols-1 md:grid-cols-2 gap-x-8">"#);
    for f in &fields {
        let value = values.get(&f.name).map(String::as_str).unwrap_or("");
        let help = f
            .help
            .as_deref()
            .filter(|h| !h.is_empty())
            .map(|h| format!(r#"<span class="label-text-alt opacity-60">{}</span>"#, html_escape(h)))
            .unwrap_or_default();
        let span = if f.field_type == "text" { " md:col-span-2" } else { "" };
        body.push_str(&format!(
            r#"<label class="form-control mb-3{span}"><div class="label"><span class="label-text">{label}</span>{help}</div>{widget}</label>"#,
            span = span,
            label = html_escape(&f.label),
            help = help,
            widget = widget(f, value),
        ));
    }
    body.push_str("</div>");
    body
}

/// The input widget for a custom field, matching the core form styling.
fn widget(f: &CustomField, value: &str) -> String {
    let name = html_escape(&f.name);
    let val = html_escape(value);
    match f.field_type.as_str() {
        "text" => format!(
            r#"<textarea name="{name}" class="textarea textarea-bordered w-full" rows="3">{val}</textarea>"#
        ),
        "number" | "monetary" => format!(
            r#"<input type="number" step="any" name="{name}" value="{val}" class="input input-bordered w-full"/>"#
        ),
        "boolean" => {
            let checked = if value == "true" || value == "t" { " checked" } else { "" };
            format!(r#"<input type="checkbox" name="{name}" class="toggle toggle-primary"{checked}/>"#)
        }
        "date" => format!(
            r#"<input type="date" name="{name}" value="{val}" class="input input-bordered w-full"/>"#
        ),
        "datetime" => {
            let local = value.get(..16).unwrap_or(value).replace(' ', "T");
            format!(
                r#"<input type="datetime-local" name="{name}" value="{}" class="input input-bordered w-full"/>"#,
                html_escape(&local)
            )
        }
        "selection" => {
            let mut out = format!(r#"<select name="{name}" class="select select-bordered w-full"><option value=""></option>"#);
            for opt in &f.selection_options {
                let selected = if opt == value { " selected" } else { "" };
                out.push_str(&format!(
                    r#"<option value="{o}"{selected}>{o}</option>"#,
                    o = html_escape(opt)
                ));
            }
            out.push_str("</select>");
            out
        }
        // "string" and any unexpected type → single-line text.
        _ => format!(
            r#"<input type="text" name="{name}" value="{val}" maxlength="255" class="input input-bordered w-full"/>"#
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation() {
        assert!(valid_name("x_priority"));
        assert!(valid_name("x_2nd_ref"));
        assert!(!valid_name("priority"), "must be x_-prefixed");
        assert!(!valid_name("x_"), "needs a body");
        assert!(!valid_name("x_Bad"), "no uppercase");
        assert!(!valid_name("x_a; drop"), "no punctuation");
    }

    #[test]
    fn type_validation() {
        assert!(is_valid_type("selection"));
        assert!(is_valid_type("monetary"));
        assert!(!is_valid_type("many2one"), "relational types not offered");
        assert!(!is_valid_type("nonsense"));
    }

    /// Full loop against a real database. Runs only when `VORTEX_TEST_DB`
    /// points at a provisioned throwaway DB (migrated, so `contacts` is
    /// registered and migration 137 is applied); otherwise it skips.
    #[tokio::test]
    async fn end_to_end_against_db() {
        let Ok(url) = std::env::var("VORTEX_TEST_DB") else {
            eprintln!("skip end_to_end_against_db: VORTEX_TEST_DB unset");
            return;
        };
        let db = PgPool::connect(&url).await.expect("connect");

        // Add a custom selection field to the (derive-registered) contacts model.
        add(&db, "contacts", "x_priority", "Priority", "selection",
            &["low".into(), "high".into()], Some("Ops priority"))
            .await
            .expect("add");

        // It renders on the model's form (create mode).
        let html = render_for_form(&db, "contacts", None).await;
        assert!(html.contains("Custom Fields"), "section header");
        assert!(html.contains(r#"name="x_priority""#), "field input present");
        assert!(html.contains("Priority"), "label present");

        // Save + load round-trip for a record.
        let rec = Uuid::new_v4();
        save_values(&db, "contacts", rec, &[("x_priority".into(), "high".into())])
            .await
            .expect("save");
        let vals = load_values(&db, "contacts", rec).await;
        assert_eq!(vals.get("x_priority").map(String::as_str), Some("high"));

        // Edit-mode render pre-selects the stored value.
        let edit_html = render_for_form(&db, "contacts", Some(&rec.to_string())).await;
        assert!(
            edit_html.contains(r#"<option value="high" selected>"#),
            "stored value pre-selected on edit"
        );

        // A custom field is listed for admin.
        assert!(list_all(&db).await.iter().any(|(m, _, f)| m == "contacts" && f.name == "x_priority"));

        // Cleanup so the test is idempotent.
        delete(&db, "contacts", "x_priority").await.expect("delete");
        sqlx::query("DELETE FROM ir_custom_value WHERE model_name = 'contacts' AND record_id = $1")
            .bind(rec).execute(&db).await.ok();
        assert!(render_for_form(&db, "contacts", None).await.is_empty(), "no custom fields after delete");
    }

    #[test]
    fn widgets_render_by_type() {
        let f = |t: &str| CustomField {
            name: "x_f".into(), label: "F".into(), field_type: t.into(),
            selection_options: vec!["a".into(), "b".into()], help: None,
            sequence: 10, is_visible: true,
        };
        assert!(widget(&f("text"), "").contains("<textarea"));
        assert!(widget(&f("number"), "3").contains(r#"type="number""#));
        assert!(widget(&f("boolean"), "true").contains(" checked"));
        assert!(widget(&f("selection"), "b").contains(r#"<option value="b" selected>"#));
        assert!(widget(&f("string"), "<x>").contains("&lt;x&gt;"), "escapes value");
    }
}
