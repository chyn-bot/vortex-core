//! [`IwkPlugin`] — the Plugin impl. Everything is declarative:
//! state what you have, the host wires it.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;

use crate::handlers;

const MIG_001_INIT: &str = include_str!("../migrations/001_init/postgres.sql");
const MIG_002_GL: &str = include_str!("../migrations/002_gl/postgres.sql");

pub struct IwkPlugin;

impl IwkPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IwkPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for IwkPlugin {
    fn technical_name(&self) -> &'static str {
        "iwk"
    }

    fn display_name(&self) -> &'static str {
        "IWK Billing"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn routes(&self) -> Router<Arc<AppState>> {
        handlers::routes()
    }

    /// Anonymous portal surface — tenant-resolved from the request
    /// Host and 404 for tenants without this module installed.
    fn public_routes(&self) -> Router<Arc<AppState>> {
        handlers::public_routes()
    }

    /// Model-registry projection (Initiative #1). The host syncs these into
    /// `ir_model` / `ir_model_field` after migrations, so the registry always
    /// mirrors the code — no hand-seeded SQL in the migration.
    fn models(&self) -> Vec<&'static vortex_plugin_sdk::orm::model::ModelMeta> {
        vec![<crate::model::IwkBill as vortex_plugin_sdk::orm::model::Model>::meta()]
    }

    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![
            MenuEntry::new("iwk.bills", "IWK Bills", "/iwk", MenuGroup::Operations)
                .with_icon("file-text")
                .with_priority(50),
            MenuEntry::new("iwk.gl", "GL & Reconciliation", "/iwk/gl", MenuGroup::Operations)
                .with_icon("book-open")
                .with_priority(51),
        ]
    }

    /// Plugin-owned schema, applied per tenant on install.
    fn migrations(&self) -> Vec<PluginMigration> {
        vec![
            PluginMigration {
                name: "001_init",
                up_sql: MIG_001_INIT,
                down_sql: None,
                // record_stages (status bar) and the model registry are
                // core features this migration seeds rows into.
                requires_core_migration: Some("124_record_stages"),
            },
            PluginMigration {
                // Seeds dedicated GL accounts (guarded on acc_account) and the
                // iwk_gl_batch posting ledger. IWK registers after accounting
                // so acc_account exists here.
                name: "002_gl",
                up_sql: MIG_002_GL,
                down_sql: None,
                requires_core_migration: Some("124_record_stages"),
            },
        ]
    }
}
