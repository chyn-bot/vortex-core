//! Validation + persistence: submitted form pairs → validated INSERT
//! or UPDATE with uniform text binds and server-side casts.

use std::collections::BTreeMap;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::config::{FieldKind, FormConfig};
use super::ident;

/// Submitted or loaded values, keyed by field name. Everything is a
/// string at this layer; types are enforced on the way into SQL.
pub type FormValues = BTreeMap<String, String>;

/// One validation failure, addressed to a field.
#[derive(Debug, Clone)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

/// Result of a save attempt: the record id, or the errors to
/// re-render the form with.
pub enum SaveOutcome {
    Saved(Uuid),
    Invalid { values: FormValues, errors: Vec<FieldError> },
}

/// Normalize raw urlencoded pairs against the config: unknown keys
/// are dropped (mass-assignment protection), checkboxes become
/// "true"/"false", whitespace is trimmed.
fn normalize(config: &FormConfig, pairs: &[(String, String)]) -> FormValues {
    let mut values = FormValues::new();
    for field in config.fields() {
        let raw = pairs.iter().rev().find(|(k, _)| k == &field.name).map(|(_, v)| v.trim());
        let value = match &field.kind {
            FieldKind::Checkbox => {
                // Browsers omit unchecked boxes entirely.
                Some(if matches!(raw, Some("on") | Some("true")) { "true" } else { "false" })
            }
            _ => raw,
        };
        if let Some(v) = value {
            values.insert(field.name.clone(), v.to_string());
        }
    }
    values
}

/// Validate normalized values. Returns errors for missing required
/// fields, non-numeric numbers, unknown select options, and malformed
/// references.
fn validate(config: &FormConfig, values: &FormValues) -> Vec<FieldError> {
    let mut errors = Vec::new();
    for field in config.fields() {
        if field.readonly {
            continue;
        }
        let value = values.get(&field.name).map(String::as_str).unwrap_or("");
        if value.is_empty() {
            if field.required {
                errors.push(FieldError {
                    field: field.name.clone(),
                    message: format!("{} is required", field.label),
                });
            }
            continue;
        }
        match &field.kind {
            FieldKind::Number => {
                if value.parse::<f64>().is_err() {
                    errors.push(FieldError {
                        field: field.name.clone(),
                        message: format!("{} must be a number", field.label),
                    });
                }
            }
            FieldKind::Select(options) => {
                if !options.iter().any(|(code, _)| code == value) {
                    errors.push(FieldError {
                        field: field.name.clone(),
                        message: format!("{} has an invalid choice", field.label),
                    });
                }
            }
            FieldKind::Many2One { .. } => {
                if Uuid::parse_str(value).is_err() {
                    errors.push(FieldError {
                        field: field.name.clone(),
                        message: format!("{} has an invalid reference", field.label),
                    });
                }
            }
            FieldKind::Json => {
                if serde_json::from_str::<serde_json::Value>(value).is_err() {
                    errors.push(FieldError {
                        field: field.name.clone(),
                        message: format!("{} must be valid JSON", field.label),
                    });
                }
            }
            _ => {}
        }
    }
    errors
}

/// SQL cast suffix for a field kind (uniform text binds).
fn cast(kind: &FieldKind) -> &'static str {
    match kind {
        FieldKind::Number => "::numeric",
        FieldKind::Date => "::date",
        FieldKind::DateTime => "::timestamptz",
        FieldKind::Checkbox => "::boolean",
        FieldKind::Many2One { .. } => "::uuid",
        FieldKind::Json => "::jsonb",
        _ => "",
    }
}

/// Writable (non-readonly) fields of the config, with identifiers
/// verified. Returns an error string on a bad identifier — that is a
/// programming error in the config, not user input.
fn writable_fields(config: &FormConfig) -> Result<Vec<&super::config::FormField>, String> {
    if !ident(&config.table) {
        return Err(format!("invalid table identifier {:?}", config.table));
    }
    let fields: Vec<_> = config.fields().filter(|f| !f.readonly).collect();
    for f in &fields {
        if !ident(&f.name) {
            return Err(format!("invalid field identifier {:?}", f.name));
        }
    }
    Ok(fields)
}

/// Build the INSERT statement for the config's writable fields.
/// Placeholders are `$1..$n` in field order; `RETURNING id`.
pub(crate) fn build_insert(config: &FormConfig) -> Result<(String, Vec<String>), String> {
    let fields = writable_fields(config)?;
    if fields.is_empty() {
        return Err("form has no writable fields".into());
    }
    let names: Vec<String> = fields.iter().map(|f| f.name.clone()).collect();
    let cols = names.join(", ");
    let placeholders: Vec<String> = fields
        .iter()
        .enumerate()
        .map(|(i, f)| format!("${}{}", i + 1, cast(&f.kind)))
        .collect();
    Ok((
        format!(
            "INSERT INTO {} ({}) VALUES ({}) RETURNING id",
            config.table,
            cols,
            placeholders.join(", ")
        ),
        names,
    ))
}

/// Build the UPDATE statement; `$last` is the record id.
pub(crate) fn build_update(config: &FormConfig) -> Result<(String, Vec<String>), String> {
    let fields = writable_fields(config)?;
    if fields.is_empty() {
        return Err("form has no writable fields".into());
    }
    let names: Vec<String> = fields.iter().map(|f| f.name.clone()).collect();
    let sets: Vec<String> = fields
        .iter()
        .enumerate()
        .map(|(i, f)| format!("{} = ${}{}", f.name, i + 1, cast(&f.kind)))
        .collect();
    Ok((
        format!(
            "UPDATE {} SET {}, updated_at = NOW() WHERE id = ${} RETURNING id",
            config.table,
            sets.join(", "),
            fields.len() + 1
        ),
        names,
    ))
}

/// Validate and persist a submission. `record` is `None` for create,
/// `Some(id)` for update. On validation failure the normalized values
/// come back so the form re-renders with the user's input intact.
pub async fn execute_form_save(
    db: &PgPool,
    config: &FormConfig,
    pairs: &[(String, String)],
    record: Option<Uuid>,
) -> Result<SaveOutcome, String> {
    let values = normalize(config, pairs);
    let errors = validate(config, &values);
    if !errors.is_empty() {
        return Ok(SaveOutcome::Invalid { values, errors });
    }

    let (sql, names) = match record {
        None => build_insert(config)?,
        Some(_) => build_update(config)?,
    };
    let mut query = sqlx::query_scalar::<_, Uuid>(&sql);
    for name in &names {
        // Empty optional input → NULL (uniform Option<&str> binds).
        let bound = values.get(name).map(String::as_str).filter(|v| !v.is_empty());
        query = query.bind(bound.map(str::to_string));
    }
    if let Some(id) = record {
        query = query.bind(id);
    }
    let id = query
        .fetch_one(db)
        .await
        .map_err(|e| format!("save failed: {e}"))?;

    // Persist any per-tenant custom-field values submitted alongside the record.
    // No-op when the model has no custom fields, so existing forms are
    // unaffected. Best-effort: a custom-store failure must not roll back the
    // record save the user just made.
    if let Err(e) = crate::custom_fields::save_values(db, &config.table, id, pairs).await {
        tracing::warn!("custom field save for {} {} failed: {}", config.table, id, e);
    }

    // Recompute and persist any computed / related virtual fields for this
    // record (merged into the same overflow store). No-op when the model has
    // none; best-effort so it never rolls back the record save.
    if let Err(e) = crate::computed_fields::store_values(db, &config.table, id).await {
        tracing::warn!("computed field store for {} {} failed: {}", config.table, id, e);
    }

    // Fire no-code automation rules for this model + trigger. No-op when the
    // model has no rules. Actions write the row directly, so they cannot
    // re-enter this save path.
    let trigger = if record.is_some() { "update" } else { "create" };
    let _ = crate::automation::run_rules(db, &config.table, trigger, id).await;

    Ok(SaveOutcome::Saved(id))
}

/// Load a record's field values as strings for Edit-mode rendering.
/// `Ok(None)` when the id doesn't exist.
pub async fn load_record(
    db: &PgPool,
    config: &FormConfig,
    id: Uuid,
) -> Result<Option<FormValues>, String> {
    if !ident(&config.table) {
        return Err(format!("invalid table identifier {:?}", config.table));
    }
    let mut selects = Vec::new();
    for f in config.fields() {
        if !ident(&f.name) {
            return Err(format!("invalid field identifier {:?}", f.name));
        }
        selects.push(format!("{name}::text AS {name}", name = f.name));
    }
    let sql = format!("SELECT {} FROM {} WHERE id = $1", selects.join(", "), config.table);
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(|e| format!("load failed: {e}"))?;
    Ok(row.map(|row| {
        let mut values = FormValues::new();
        for f in config.fields() {
            if let Ok(Some(v)) = row.try_get::<Option<String>, _>(f.name.as_str()) {
                values.insert(f.name.clone(), v);
            }
        }
        values
    }))
}

#[cfg(test)]
mod tests {
    use super::super::config::{FormConfig, FormField};
    use super::*;

    fn cfg() -> FormConfig {
        FormConfig::new("Item", "parking_item", "/parking")
            .field(FormField::text("name", "Name").required())
            .field(FormField::textarea("description", "Description"))
            .field(FormField::number("spaces", "Spaces"))
            .field(FormField::checkbox("active", "Active"))
            .field(FormField::select("record_state", "State", &[("draft", "Draft")]))
            .field(FormField::many2one("zone_id", "Zone", "parking_zone"))
            .field(FormField::text("code", "Code").readonly())
    }

    fn pairs(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn insert_sql_casts_and_skips_readonly() {
        let (sql, names) = build_insert(&cfg()).unwrap();
        assert_eq!(
            sql,
            "INSERT INTO parking_item (name, description, spaces, active, record_state, zone_id) \
             VALUES ($1, $2, $3::numeric, $4::boolean, $5, $6::uuid) RETURNING id"
        );
        assert!(!names.contains(&"code".to_string()));
    }

    #[test]
    fn update_sql_binds_id_last() {
        let (sql, _) = build_update(&cfg()).unwrap();
        assert!(sql.starts_with("UPDATE parking_item SET name = $1, "));
        assert!(sql.contains("zone_id = $6::uuid"));
        assert!(sql.ends_with("updated_at = NOW() WHERE id = $7 RETURNING id"));
    }

    #[test]
    fn validation_catches_each_kind() {
        let c = cfg();
        let v = normalize(&c, &pairs(&[
            ("name", ""),
            ("spaces", "not-a-number"),
            ("record_state", "bogus"),
            ("zone_id", "not-a-uuid"),
            ("ignored_extra", "dropped"),
        ]));
        assert!(!v.contains_key("ignored_extra"), "unknown keys must be dropped");
        let errors = validate(&c, &v);
        let fields: Vec<&str> = errors.iter().map(|e| e.field.as_str()).collect();
        assert_eq!(fields, vec!["name", "spaces", "record_state", "zone_id"]);
    }

    #[test]
    fn checkbox_absent_means_false() {
        let c = cfg();
        let v = normalize(&c, &pairs(&[("name", "x")]));
        assert_eq!(v.get("active").map(String::as_str), Some("false"));
        let v = normalize(&c, &pairs(&[("name", "x"), ("active", "on")]));
        assert_eq!(v.get("active").map(String::as_str), Some("true"));
    }

    #[test]
    fn bad_identifiers_are_config_errors() {
        let bad = FormConfig::new("X", "t; DROP TABLE users", "/x")
            .field(FormField::text("name", "Name"));
        assert!(build_insert(&bad).is_err());
        let bad = FormConfig::new("X", "items", "/x")
            .field(FormField::text("name\"; --", "Name"));
        assert!(build_insert(&bad).is_err());
    }
}
