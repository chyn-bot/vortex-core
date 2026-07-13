//! Generate default list & form configs from a model's `#[derive(Model)]`
//! metadata (Initiative #6).
//!
//! A large fraction of plugin UI is a hand-assembled [`ListConfig`] /
//! [`FormConfig`] that just mirrors the model's fields. Since Initiative #1 made
//! `ModelMeta` the single source of truth, we can *derive* a sensible default
//! straight from it — so a new model gets a working list + form for free, and
//! bespoke screens become the override, not the baseline.
//!
//! ```ignore
//! // Everything the model implies, then override only what's special:
//! let list = ListConfig::from_model(MyModel::meta())
//!     .detail_url("/my/{id}")
//!     .create("New", "/my/new");
//! let form = FormConfig::from_model(MyModel::meta(), "/my");
//! ```
//!
//! The mapping is intentionally conservative: it skips the primary key, audit
//! columns, non-stored computed fields, and types with no obvious widget
//! (binary/array), and it maps the registry's semantic hints (`ui_type`,
//! `selection`, foreign-key `Reference`) to the right widget/renderer.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use vortex_orm::field::{FieldDef, FieldType};
use vortex_orm::model::ModelMeta;

use crate::form::{FormConfig, FormField};
use crate::list::{ListColumn, ListConfig};

/// Columns the generator never surfaces: the identity key and the conventional
/// audit / system columns every model carries.
const SYSTEM_COLUMNS: &[&str] = &[
    "id", "created_at", "updated_at", "created_by", "updated_by", "deleted_at",
    "create_date", "write_date", "company_id",
];

/// Max columns a generated list shows, so a wide model doesn't produce an
/// unreadable table. Bespoke lists override.
const MAX_LIST_COLUMNS: usize = 6;

/// Title-case a snake_case identifier (`credit_limit` → `Credit Limit`).
fn humanize(name: &str) -> String {
    name.split('_')
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Intern a synthesized string to `&'static str`. The declarative
/// [`ListConfig`] takes `&'static str`; field/table names borrow directly from
/// the `'static` [`ModelMeta`], but *humanized* labels are freshly built, so
/// they need interning. The pool dedups, so each distinct label leaks at most
/// once (bounded by the number of model fields — a handful per process).
fn intern(s: &str) -> &'static str {
    static POOL: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let pool = POOL.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = pool.lock().unwrap();
    if let Some(&existing) = guard.get(s) {
        return existing;
    }
    let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
    guard.insert(leaked);
    leaked
}

/// The widget category a field maps to. Drives both the form field kind and
/// whether/how the column appears in the list.
enum Widget {
    /// Not surfaced (pk, computed, audit column, binary/array, …).
    Skip,
    Text,
    TextArea,
    Number,
    Checkbox,
    Date,
    DateTime,
    Json,
    /// Fixed-choice list: (value, label) pairs.
    Select(Vec<(String, String)>),
    /// Foreign key to `table` (display column `name`).
    Many2One(String),
}

/// Classify a field into a widget, honoring the registry's semantic hints in
/// the same precedence the registry sync uses: reference → selection/enum →
/// `ui_type` override → storage default.
fn widget_for(f: &FieldDef) -> Widget {
    if f.primary_key
        || matches!(f.field_type, FieldType::Computed)
        || SYSTEM_COLUMNS.contains(&f.name.as_str())
    {
        return Widget::Skip;
    }

    // A foreign key is a reference picker regardless of any other hint.
    if let FieldType::Reference { model, .. } = &f.field_type {
        return Widget::Many2One(model.clone());
    }

    // Explicit selection options, or a stored enum's own values.
    if !f.selection.is_empty() {
        return Widget::Select(f.selection.iter().map(|v| (v.clone(), humanize(v))).collect());
    }
    if let FieldType::Enum { values, .. } = &f.field_type {
        return Widget::Select(values.iter().map(|v| (v.clone(), humanize(v))).collect());
    }

    // Semantic `ui_type` override (e.g. a stored Double flagged `monetary`).
    if let Some(w) = f.ui_type.as_deref() {
        match w {
            "text" => return Widget::TextArea,
            "monetary" | "number" | "integer" | "float" | "decimal" => return Widget::Number,
            "date" => return Widget::Date,
            "datetime" => return Widget::DateTime,
            "boolean" => return Widget::Checkbox,
            "json" => return Widget::Json,
            "string" | "char" => return Widget::Text,
            _ => {}
        }
    }

    // Storage-type default.
    match &f.field_type {
        FieldType::Boolean => Widget::Checkbox,
        FieldType::Serial
        | FieldType::Integer
        | FieldType::BigInt
        | FieldType::Float
        | FieldType::Double
        | FieldType::Decimal { .. } => Widget::Number,
        FieldType::Date => Widget::Date,
        FieldType::Timestamp => Widget::DateTime,
        FieldType::Json => Widget::Json,
        FieldType::String { .. } | FieldType::Text | FieldType::Time | FieldType::Uuid => {
            Widget::Text
        }
        FieldType::Binary | FieldType::Array(_) => Widget::Skip,
        // Handled above, but keep the match exhaustive.
        FieldType::Reference { .. } | FieldType::Enum { .. } | FieldType::Computed => Widget::Skip,
    }
}

// ── FormConfig ────────────────────────────────────────────────────────────

/// Build the [`FormField`] for a single field, or `None` if it shouldn't appear
/// on a form (pk, system column, computed, no-widget type).
fn form_field_for(f: &FieldDef) -> Option<FormField> {
    let label = f.label.clone().unwrap_or_else(|| humanize(&f.name));
    let mut field = match widget_for(f) {
        Widget::Skip => return None,
        Widget::Text => FormField::text(&f.name, &label),
        Widget::TextArea => FormField::textarea(&f.name, &label),
        Widget::Number => FormField::number(&f.name, &label),
        Widget::Checkbox => FormField::checkbox(&f.name, &label),
        Widget::Date => FormField::date(&f.name, &label),
        Widget::DateTime => FormField::datetime(&f.name, &label),
        Widget::Json => FormField::json(&f.name, &label),
        Widget::Select(opts) => {
            let refs: Vec<(&str, &str)> = opts.iter().map(|(v, l)| (v.as_str(), l.as_str())).collect();
            FormField::select(&f.name, &label, &refs)
        }
        Widget::Many2One(table) => FormField::many2one(&f.name, &label, &table),
    };
    if f.required {
        field = field.required();
    }
    if f.readonly {
        field = field.readonly();
    }
    Some(field)
}

impl FormConfig {
    /// Build a default form for `meta`: one field per stored, non-system column,
    /// widget chosen from the field's type/semantic hints. `base_url` is the
    /// owning module's URL base (used for the cancel link and post-save
    /// redirect). Chain the normal builders to override.
    pub fn from_model(meta: &ModelMeta, base_url: &str) -> FormConfig {
        let title = meta.label.clone().unwrap_or_else(|| humanize(&meta.name));
        let mut config = FormConfig::new(&title, &meta.table, base_url);
        for f in meta.fields_ordered() {
            if let Some(field) = form_field_for(f) {
                config = config.field(field);
            }
        }
        config
    }

    /// Like [`FormConfig::from_model`] but generates fields for exactly the
    /// named columns, in the given order — for when a curated subset is wanted
    /// (e.g. omit auto-stamped or status-managed columns). Names that are
    /// unknown, the primary key, a system column, or a no-widget type are
    /// silently skipped.
    pub fn from_model_fields(meta: &ModelMeta, base_url: &str, include: &[&str]) -> FormConfig {
        let title = meta.label.clone().unwrap_or_else(|| humanize(&meta.name));
        let mut config = FormConfig::new(&title, &meta.table, base_url);
        for name in include {
            if let Some(field) = meta.get_field(name).and_then(form_field_for) {
                config = config.field(field);
            }
        }
        config
    }
}

// ── ListConfig ────────────────────────────────────────────────────────────

/// Whether a widget is worth a default *list* column. Long text, JSON, and
/// foreign keys (which would show a raw UUID) are omitted from the default
/// table — they stay available on the form.
fn lists_well(w: &Widget) -> bool {
    matches!(
        w,
        Widget::Text | Widget::Number | Widget::Checkbox | Widget::Date | Widget::DateTime | Widget::Select(_)
    )
}

impl ListConfig {
    /// Build a default list for `meta`: a capped set of scalar columns, text
    /// columns searchable, booleans rendered as badges, sorted by `name` when
    /// present. Requires a `'static` meta (as returned by `Model::meta()`) so
    /// the field/table names borrow directly. Chain `.detail_url()` /
    /// `.create()` / `.pivot_url()` to finish it.
    pub fn from_model(meta: &'static ModelMeta) -> ListConfig {
        let title = meta
            .label
            .as_deref()
            .unwrap_or_else(|| intern(&humanize(&meta.name)));
        let mut config = ListConfig::new(title, &meta.table);

        let mut has_name = false;
        let mut first_field: Option<&'static str> = None;
        let mut count = 0;

        for f in meta.fields_ordered() {
            if count >= MAX_LIST_COLUMNS {
                break;
            }
            let widget = widget_for(f);
            if !lists_well(&widget) {
                continue;
            }
            let field: &'static str = f.name.as_str();
            let label: &'static str =
                f.label.as_deref().unwrap_or_else(|| intern(&humanize(&f.name)));

            let mut col = ListColumn::new(field, label).sortable();
            match &widget {
                // Text-ish columns feed the free-text search.
                Widget::Text | Widget::Select(_) => col = col.searchable(),
                Widget::Checkbox => col = col.bool_badge("Yes", "badge-success", "No", "badge-ghost"),
                _ => {}
            }

            config = config.column(col);
            if field == "name" {
                has_name = true;
            }
            first_field.get_or_insert(field);
            count += 1;
        }

        // Sort by the most natural key available.
        let sort = if has_name { "name" } else { first_field.unwrap_or("id") };
        config.default_sort(sort)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vortex_orm::field::{FieldType, OnDelete};

    /// A representative model: pk + audit columns to skip, and one of each
    /// widget-worthy kind.
    fn sample_meta() -> ModelMeta {
        let mut m = ModelMeta::new("Widget", "widgets");
        m.add_field(FieldDef::new("id", FieldType::Uuid).primary_key());
        m.add_field(FieldDef::new("name", FieldType::String { max_length: Some(255) }).required());
        m.add_field(FieldDef::new("description", FieldType::Text).with_ui_type("text"));
        m.add_field(FieldDef::new("qty", FieldType::Integer));
        m.add_field(
            FieldDef::new("price", FieldType::Double).with_ui_type("monetary").with_label("Unit Price"),
        );
        m.add_field(FieldDef::new("active", FieldType::Boolean));
        m.add_field(FieldDef::new("due", FieldType::Date));
        m.add_field(
            FieldDef::new("state", FieldType::Text)
                .with_selection(vec!["draft".into(), "done".into()]),
        );
        m.add_field(FieldDef::new(
            "partner_id",
            FieldType::Reference { model: "contacts".into(), on_delete: OnDelete::Restrict },
        ));
        m.add_field(FieldDef::new("payload", FieldType::Json));
        // System columns that must be skipped everywhere.
        m.add_field(FieldDef::new("created_at", FieldType::Timestamp));
        m.add_field(FieldDef::new("company_id", FieldType::Uuid));
        m
    }

    #[test]
    fn form_maps_widgets_and_skips_system_columns() {
        let meta = sample_meta();
        let form = FormConfig::from_model(&meta, "/widgets/");
        assert_eq!(form.table, "widgets");
        assert_eq!(form.base_url, "/widgets"); // trailing slash trimmed

        let names: Vec<&str> = form.fields().map(|f| f.name.as_str()).collect();
        // pk + audit + company skipped; everything else present.
        assert!(!names.contains(&"id"));
        assert!(!names.contains(&"created_at"));
        assert!(!names.contains(&"company_id"));
        assert_eq!(
            names,
            vec!["name", "description", "qty", "price", "active", "due", "state", "partner_id", "payload"]
        );

        use crate::form::FieldKind;
        let by = |n: &str| form.fields().find(|f| f.name == n).unwrap().clone();
        assert!(matches!(by("description").kind, FieldKind::TextArea));
        assert!(matches!(by("qty").kind, FieldKind::Number));
        assert!(matches!(by("price").kind, FieldKind::Number)); // monetary → number widget
        assert_eq!(by("price").label, "Unit Price"); // explicit label wins
        assert!(matches!(by("active").kind, FieldKind::Checkbox));
        assert!(matches!(by("due").kind, FieldKind::Date));
        assert!(matches!(by("state").kind, FieldKind::Select(_)));
        assert!(matches!(by("partner_id").kind, FieldKind::Many2One { .. }));
        assert!(matches!(by("payload").kind, FieldKind::Json));
        assert!(by("name").required, "required flag carried through");
        // Humanized default label.
        assert_eq!(by("qty").label, "Qty");
    }

    #[test]
    fn from_model_fields_picks_named_subset_in_order() {
        let meta = sample_meta();
        let form = FormConfig::from_model_fields(&meta, "/widgets", &["description", "name", "id", "nope"]);
        let names: Vec<&str> = form.fields().map(|f| f.name.as_str()).collect();
        // Given order honored; pk ("id") and unknown ("nope") dropped.
        assert_eq!(names, vec!["description", "name"]);
    }

    #[test]
    fn list_caps_columns_skips_nonscalar_and_sorts_by_name() {
        let meta: &'static ModelMeta = Box::leak(Box::new(sample_meta()));
        let list = ListConfig::from_model(meta);
        assert_eq!(list.table, "widgets");
        assert_eq!(list.default_sort, "name");

        let cols: Vec<&str> = list.columns.iter().map(|c| c.field).collect();
        // Capped at 6; long-text/json/many2one omitted from the table.
        assert!(cols.len() <= super::MAX_LIST_COLUMNS);
        assert!(!cols.contains(&"description"), "textarea omitted from list");
        assert!(!cols.contains(&"payload"), "json omitted");
        assert!(!cols.contains(&"partner_id"), "m2o omitted (would show a uuid)");
        assert!(cols.contains(&"name") && cols.contains(&"state"));

        // name is searchable; active renders as a bool badge.
        let name_col = list.columns.iter().find(|c| c.field == "name").unwrap();
        assert!(name_col.searchable);
        let active_col = list.columns.iter().find(|c| c.field == "active").unwrap();
        assert!(matches!(active_col.renderer, crate::list::CellRenderer::BoolBadge { .. }));
    }

    #[test]
    fn list_falls_back_to_first_column_when_no_name() {
        let mut m = ModelMeta::new("Log", "logs");
        m.add_field(FieldDef::new("id", FieldType::Uuid).primary_key());
        m.add_field(FieldDef::new("code", FieldType::String { max_length: Some(20) }));
        m.add_field(FieldDef::new("level", FieldType::Integer));
        let meta: &'static ModelMeta = Box::leak(Box::new(m));
        let list = ListConfig::from_model(meta);
        assert_eq!(list.default_sort, "code", "no name → first scalar column");
    }

    #[test]
    fn intern_dedups() {
        let a = intern("Hello World");
        let b = intern("Hello World");
        assert_eq!(a.as_ptr(), b.as_ptr(), "same string interned once");
    }
}
