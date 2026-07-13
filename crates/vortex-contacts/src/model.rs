//! The `Contact` model — declared with `#[derive(Model)]`.
//!
//! This is the **registry source of truth** for the core `contacts` table:
//! `Plugin::models()` returns `Contact::meta()`, and the host projects it into
//! `ir_model` / `ir_model_field` after migrations (see
//! `vortex_orm::registry_sync`). It began as an exact reproduction of the rows
//! migration `003_pivot_metadata` hand-seeded, but now models the **full** set
//! of business columns on the table (contact details, address, notes) — so
//! every real field is registered and therefore available to the generic list /
//! pivot / API, custom-field placement anchors, and reporting. The old
//! hand-seed SQL in migration 003 is redundant.
//!
//! The `contacts` table itself is a **core** table (contacts/partners is a core
//! concept); this struct is the registry projection the plugin owns, not the
//! DDL. System columns (`company_id`, timestamps, `created_by`/`updated_by`) and
//! the primary key are excluded from the registry by convention; `display_name`
//! and `record_state` are managed by the framework (name compositor / status
//! bar) rather than entered as fields, so they are omitted too.

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

    #[vortex(label = "Email", ui_type = "string")]
    pub email: Option<String>,

    #[vortex(label = "Phone", ui_type = "string")]
    pub phone: Option<String>,

    #[vortex(label = "Mobile", ui_type = "string")]
    pub mobile: Option<String>,

    #[vortex(label = "VAT Number", ui_type = "string")]
    pub vat_number: Option<String>,

    #[vortex(label = "Street", ui_type = "string")]
    pub street: Option<String>,

    #[vortex(label = "Street 2", ui_type = "string")]
    pub street2: Option<String>,

    #[vortex(label = "Street 3", ui_type = "string")]
    pub street3: Option<String>,

    #[vortex(label = "City", ui_type = "string")]
    pub city: Option<String>,

    #[vortex(label = "Postcode", ui_type = "string")]
    pub zip: Option<String>,

    #[vortex(label = "State", references = "states")]
    pub state_id: Option<Uuid>,

    #[vortex(label = "Country", references = "countries")]
    pub country_id: Option<Uuid>,

    #[vortex(label = "Parent", references = "contacts")]
    pub parent_id: Option<Uuid>,

    #[vortex(label = "Credit Limit", ui_type = "monetary")]
    pub credit_limit: Option<f64>,

    #[vortex(label = "Notes", ui_type = "text")]
    pub notes: Option<String>,

    #[vortex(label = "Active")]
    pub active: bool,
}
