//! # Form engine — declarative record forms
//!
//! The counterpart to the list framework: declare a form once, get
//! rendering, validation, and persistence. Handlers shrink to
//! *authorize → save → audit → redirect*; the engine owns the HTML,
//! the type-safe SQL, and the error round-trip.
//!
//! ```rust,ignore
//! use vortex_framework::form::{execute_form_save, render_form, FormConfig, FormField, FormMode};
//!
//! fn item_form() -> FormConfig {
//!     FormConfig::new("Parking Item", "parking_item", "/parking")
//!         .section("Details")
//!         .field(FormField::text("name", "Name").required())
//!         .field(FormField::select("record_state", "State", &[
//!             ("draft", "Draft"), ("confirmed", "Confirmed"),
//!         ]))
//!         .field(FormField::many2one("category_id", "Category", "categories"))
//!         .section("Notes")
//!         .field(FormField::textarea("description", "Description"))
//! }
//!
//! // GET  → Html(render_form(&cfg, FormMode::Create, &values, &errors, &ctx))
//! // POST → execute_form_save(&db, &cfg, &form_pairs, None).await
//! ```
//!
//! Design notes:
//! - **Identifiers are validated** (`[a-z0-9_]`, ≤63) before entering
//!   SQL; everything user-supplied is bound, never interpolated.
//! - **Uniform binds, server-side casts**: every value binds as
//!   `Option<&str>` and the SQL casts (`$1::numeric`, `$2::uuid`, …),
//!   so one code path covers all field kinds and Postgres enforces
//!   types. Empty optional inputs become NULL.
//! - Widgets are inferred from the declared [`FieldKind`]. When the
//!   `derive(Model)` ↔ `ir_model` unification lands, kinds will
//!   default from the registry; the builder stays the override.

mod config;
mod lookup;
mod render;
mod save;

pub use config::{FieldKind, FormConfig, FormField, FormSection};
pub use lookup::{typeahead_widget, LookupSource};
pub use render::{render_form, FormMode};
pub use save::{execute_form_save, load_record, FieldError, FormValues, SaveOutcome};

/// Postgres-safe identifier: lowercase alnum + underscore, ≤ 63 chars.
pub(crate) fn ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}
