//! The `Contact` model — declared with `#[derive(Model)]`.
//!
//! This is the **registry source of truth** for the core `contacts` table:
//! `Plugin::models()` returns `Contact::meta()`, and the host projects it into
//! `ir_model` / `ir_model_field` after migrations (see
//! `vortex_orm::registry_sync`). It reproduces exactly the rows that migration
//! `003_pivot_metadata` used to hand-seed — the same field set, types, labels,
//! `many2one` relations, selection options, and ordering — so a database
//! populated either way is identical. Once the derive path is proven at
//! runtime, the hand-seed SQL in migration 003 becomes redundant.
//!
//! The `contacts` table itself is a **core** table (contacts/partners is a core
//! concept); this struct is the registry projection the plugin owns, not the
//! DDL. It intentionally models only the registered business fields — system
//! columns (`company_id`, timestamps) and the primary key are excluded from the
//! registry, matching the original seed.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_orm::prelude::Model;

/// Registry projection of the core `contacts` table.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "contacts", module = "contacts", name = "contacts", label = "Contacts")]
pub struct Contact {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Name", ui_type = "string")]
    pub name: String,

    #[vortex(label = "Code", ui_type = "string")]
    pub code: Option<String>,

    #[vortex(label = "Type", selection = "customer,supplier,both,other")]
    pub contact_type: String,

    #[vortex(label = "Is Company")]
    pub is_company: bool,

    #[vortex(label = "City", ui_type = "string")]
    pub city: Option<String>,

    #[vortex(label = "State", references = "states")]
    pub state_id: Option<Uuid>,

    #[vortex(label = "Country", references = "countries")]
    pub country_id: Option<Uuid>,

    #[vortex(label = "Parent", references = "contacts")]
    pub parent_id: Option<Uuid>,

    #[vortex(label = "Credit Limit", ui_type = "monetary")]
    pub credit_limit: Option<f64>,

    #[vortex(label = "Active")]
    pub active: bool,
}
