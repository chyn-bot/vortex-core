//! Model-registry synchronization.
//!
//! Projects compiled [`ModelMeta`] (produced by `#[derive(Model)]`) into the
//! runtime metadata tables `ir_model` / `ir_model_field` that back the generic
//! views (`/list`, `/kanban`, `/pivot`, …) and the public REST API.
//!
//! This is the mechanism that makes `#[derive(Model)]` the **single source of
//! truth** for a model's registry metadata: instead of every plugin hand-writing
//! `INSERT INTO ir_model …` SQL in a migration (which silently drifts from the
//! Rust struct and the real table), the host calls [`sync_model_registry`] with
//! the metas a plugin exposes via `Plugin::models()`, and the rows are derived.
//!
//! The upserts are idempotent and use the same `ON CONFLICT … DO UPDATE` shape
//! as the legacy hand-seeded migrations, so a database seeded either way ends up
//! with identical rows — which is what lets the two coexist during rollout.

use crate::field::{FieldDef, FieldType};
use crate::model::ModelMeta;
use sqlx::PgPool;

/// The closed vocabulary accepted by the `ir_model_field.field_type` CHECK
/// constraint (migration 122). A `ui_type` override outside this set is
/// ignored in favour of the storage-derived default so a sync never violates
/// the constraint.
const IR_FIELD_TYPES: &[&str] = &[
    "string", "char", "text", "boolean", "integer", "float", "decimal",
    "monetary", "number", "date", "datetime", "selection", "many2one",
    "one2many", "many2many", "uuid", "json", "binary",
];

/// Resolve a [`FieldDef`] to its `(field_type, related_model, selection_options)`
/// triple for `ir_model_field`.
///
/// Precedence: a reference is always `many2one`; then an explicit selection
/// list; then a validated `ui_type` override; then the storage type default.
pub fn ir_field_type(f: &FieldDef) -> (String, Option<String>, Option<serde_json::Value>) {
    // A foreign key is a many2one regardless of any other hint.
    if let FieldType::Reference { model, .. } = &f.field_type {
        return ("many2one".to_string(), Some(model.clone()), None);
    }

    // Explicit selection options (from `#[vortex(selection = "...")]`).
    if !f.selection.is_empty() {
        return ("selection".to_string(), None, Some(selection_json(&f.selection)));
    }

    // A stored enum is a selection carrying its own values.
    if let FieldType::Enum { values, .. } = &f.field_type {
        return ("selection".to_string(), None, Some(selection_json(values)));
    }

    // Explicit UI/semantic override, validated against the CHECK vocabulary.
    if let Some(w) = &f.ui_type {
        if IR_FIELD_TYPES.contains(&w.as_str()) {
            return (w.clone(), None, None);
        }
    }

    (storage_default(&f.field_type).to_string(), None, None)
}

/// Default `ir_model_field.field_type` for a storage [`FieldType`] when no
/// semantic override is supplied.
fn storage_default(ft: &FieldType) -> &'static str {
    match ft {
        FieldType::Boolean => "boolean",
        FieldType::Serial | FieldType::Integer | FieldType::BigInt => "integer",
        FieldType::Float | FieldType::Double => "float",
        FieldType::Decimal { .. } => "decimal",
        // Short strings default to `string`; authors opt into `text` (a
        // textarea widget) via `#[vortex(ui_type = "text")]`.
        FieldType::String { .. } | FieldType::Text => "string",
        FieldType::Uuid => "uuid",
        FieldType::Date => "date",
        // No dedicated `time` type in the registry vocabulary.
        FieldType::Time | FieldType::Timestamp => "datetime",
        FieldType::Json => "json",
        FieldType::Binary => "binary",
        FieldType::Reference { .. } => "many2one",
        FieldType::Enum { .. } => "selection",
        FieldType::Array(_) => "json",
        FieldType::Computed => "string",
    }
}

fn selection_json(values: &[String]) -> serde_json::Value {
    serde_json::Value::Array(
        values.iter().map(|s| serde_json::Value::String(s.clone())).collect(),
    )
}

/// Title-case a snake_case identifier for a default display label
/// (`credit_limit` → `Credit Limit`).
fn humanize(name: &str) -> String {
    name.split('_')
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether a field is projected into `ir_model_field`. The primary key and
/// non-stored computed fields are excluded, matching the hand-seeded
/// convention (which never registered `id`).
fn is_registrable(f: &FieldDef) -> bool {
    !f.primary_key && !matches!(f.field_type, FieldType::Computed)
}

/// Upsert one model's `ir_model` row and all its `ir_model_field` rows.
async fn sync_one(pool: &PgPool, meta: &ModelMeta) -> Result<(), sqlx::Error> {
    let reg_name = meta.registry_key().to_string();
    let display = meta.label.clone().unwrap_or_else(|| humanize(&reg_name));

    let model_id: uuid::Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO ir_model (name, display_name, table_name, module)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (name) DO UPDATE
            SET display_name = EXCLUDED.display_name,
                table_name   = EXCLUDED.table_name,
                module       = EXCLUDED.module,
                is_active    = true
        RETURNING id
        "#,
    )
    .bind(&reg_name)
    .bind(&display)
    .bind(&meta.table)
    .bind(&meta.module)
    .fetch_one(pool)
    .await?;

    let mut sequence: i32 = 0;
    for field in meta.fields_ordered() {
        if !is_registrable(field) {
            continue;
        }
        sequence += 10;
        let (field_type, related_model, selection_options) = ir_field_type(field);
        let label = field.label.clone().unwrap_or_else(|| humanize(&field.name));

        sqlx::query(
            r#"
            INSERT INTO ir_model_field
                (model_id, name, display_name, field_type, related_model, selection_options, sequence)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (model_id, name) DO UPDATE
                SET display_name      = EXCLUDED.display_name,
                    field_type        = EXCLUDED.field_type,
                    related_model     = EXCLUDED.related_model,
                    selection_options = EXCLUDED.selection_options,
                    sequence          = EXCLUDED.sequence
            "#,
        )
        .bind(model_id)
        .bind(&field.name)
        .bind(&label)
        .bind(&field_type)
        .bind(related_model)
        .bind(selection_options)
        .bind(sequence)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Synchronize a batch of model metadata into `ir_model` / `ir_model_field`.
///
/// Idempotent. Returns the number of models synced. Requires that migration
/// `122_model_registry` has been applied (the tables must exist); callers run
/// it after the migration phase.
pub async fn sync_model_registry(
    pool: &PgPool,
    metas: &[&ModelMeta],
) -> Result<usize, sqlx::Error> {
    for meta in metas {
        sync_one(pool, meta).await?;
    }
    Ok(metas.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{FieldDef, FieldType, OnDelete};

    #[test]
    fn humanize_snake_case() {
        assert_eq!(humanize("credit_limit"), "Credit Limit");
        assert_eq!(humanize("name"), "Name");
        assert_eq!(humanize("is_company"), "Is Company");
    }

    #[test]
    fn reference_maps_to_many2one() {
        let mut f = FieldDef::new(
            "state_id",
            FieldType::Reference { model: "states".into(), on_delete: OnDelete::Restrict },
        );
        f.label = Some("State".into());
        let (t, related, opts) = ir_field_type(&f);
        assert_eq!(t, "many2one");
        assert_eq!(related.as_deref(), Some("states"));
        assert!(opts.is_none());
    }

    #[test]
    fn selection_wins_over_storage() {
        let mut f = FieldDef::new("contact_type", FieldType::Text);
        f.selection = vec!["customer".into(), "supplier".into()];
        let (t, related, opts) = ir_field_type(&f);
        assert_eq!(t, "selection");
        assert!(related.is_none());
        assert_eq!(opts.unwrap(), serde_json::json!(["customer", "supplier"]));
    }

    #[test]
    fn ui_type_override_is_validated() {
        let mut monetary = FieldDef::new("credit_limit", FieldType::Double);
        monetary.ui_type = Some("monetary".into());
        assert_eq!(ir_field_type(&monetary).0, "monetary");

        // An override outside the CHECK vocabulary falls back to storage default.
        let mut bogus = FieldDef::new("x", FieldType::Double);
        bogus.ui_type = Some("not_a_widget".into());
        assert_eq!(ir_field_type(&bogus).0, "float");
    }

    #[test]
    fn storage_text_defaults_to_string() {
        assert_eq!(ir_field_type(&FieldDef::new("name", FieldType::Text)).0, "string");
        assert_eq!(ir_field_type(&FieldDef::new("flag", FieldType::Boolean)).0, "boolean");
    }
}
