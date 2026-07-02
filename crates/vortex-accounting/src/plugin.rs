//! [`AccountingPlugin`] — the Plugin impl for the accounting base.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;

use crate::{handlers, handlers_documents};

const MIG_001_ACCOUNTING: &str = include_str!("../migrations/001_accounting/postgres.sql");
const MIG_002_DOCUMENTS: &str =
    include_str!("../migrations/002_accounting_documents/postgres.sql");
const MIG_003_REGISTRY: &str =
    include_str!("../migrations/003_accounting_registry/postgres.sql");

pub struct AccountingPlugin;

impl AccountingPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AccountingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for AccountingPlugin {
    fn technical_name(&self) -> &'static str {
        "accounting"
    }

    fn display_name(&self) -> &'static str {
        "Accounting"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn summary(&self) -> &'static str {
        "Chart of accounts, journals, and double-entry journal entries"
    }

    fn description(&self) -> &'static str {
        "The platform's accounting base. A flat, typed chart of accounts, five \
         standard journals, and a double-entry posting engine with DB-enforced \
         immutability of posted entries (corrections are reversals). Other \
         modules adopt it through a small service API — invoices, bills and \
         payments are journal entries, so sub-ledgers can never drift from the \
         general ledger."
    }

    fn author(&self) -> &'static str {
        "Vortex Core"
    }

    fn category(&self) -> &'static str {
        "Accounting"
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec![]
    }

    fn routes(&self) -> Router<Arc<AppState>> {
        handlers::accounting_routes().merge(handlers_documents::document_routes())
    }

    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![
            MenuEntry::new(
                "accounting.moves",
                "Journal Entries",
                "/accounting",
                MenuGroup::Operations,
            )
            .with_icon("scale")
            .with_priority(40),
            MenuEntry::new(
                "accounting.invoices",
                "Customer Invoices",
                "/accounting/invoices",
                MenuGroup::Operations,
            )
            .under("accounting.moves"),
            MenuEntry::new(
                "accounting.bills",
                "Vendor Bills",
                "/accounting/bills",
                MenuGroup::Operations,
            )
            .under("accounting.moves"),
            MenuEntry::new(
                "accounting.payments",
                "Payments",
                "/accounting/payments",
                MenuGroup::Operations,
            )
            .under("accounting.moves"),
            MenuEntry::new(
                "accounting.config",
                "Accounting Setup",
                "/accounting/accounts",
                MenuGroup::Operations,
            )
            .with_icon("settings")
            .with_priority(41),
            MenuEntry::new(
                "accounting.config.accounts",
                "Chart of Accounts",
                "/accounting/accounts",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.config.journals",
                "Journals",
                "/accounting/journals",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
        ]
    }

    /// Plugin-owned migrations. Depends on core commerce (currencies,
    /// taxes — migration 119) and core contacts (010, transitively older).
    fn migrations(&self) -> Vec<PluginMigration> {
        vec![
            PluginMigration {
                name: "001_accounting",
                up_sql: MIG_001_ACCOUNTING,
                down_sql: Some(include_str!("../migrations/001_accounting/postgres_down.sql")),
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "002_accounting_documents",
                up_sql: MIG_002_DOCUMENTS,
                down_sql: Some(include_str!(
                    "../migrations/002_accounting_documents/postgres_down.sql"
                )),
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "003_accounting_registry",
                up_sql: MIG_003_REGISTRY,
                down_sql: None,
                requires_core_migration: Some("122_model_registry"),
            },
        ]
    }

    fn reports(&self) -> Vec<ReportDef> {
        crate::reports::report_defs()
    }

    fn translations(&self) -> Vec<Translation> {
        vec![
            // English
            Translation::new("en", "accounting", "menu.title", "Accounting"),
            Translation::new("en", "accounting", "menu.moves", "Journal Entries"),
            Translation::new("en", "accounting", "menu.accounts", "Chart of Accounts"),
            Translation::new("en", "accounting", "menu.journals", "Journals"),
            Translation::new("en", "accounting", "btn.new_entry", "New Journal Entry"),
            Translation::new("en", "accounting", "btn.post", "Post"),
            Translation::new("en", "accounting", "btn.reverse", "Reverse"),
            Translation::new("en", "accounting", "field.journal", "Journal"),
            Translation::new("en", "accounting", "field.debit", "Debit"),
            Translation::new("en", "accounting", "field.credit", "Credit"),
            Translation::new("en", "accounting", "state.draft", "Draft"),
            Translation::new("en", "accounting", "state.posted", "Posted"),
            Translation::new("en", "accounting", "state.cancelled", "Cancelled"),
            // Malay
            Translation::new("ms", "accounting", "menu.title", "Perakaunan"),
            Translation::new("ms", "accounting", "menu.moves", "Catatan Jurnal"),
            Translation::new("ms", "accounting", "menu.accounts", "Carta Akaun"),
            Translation::new("ms", "accounting", "menu.journals", "Jurnal"),
            Translation::new("ms", "accounting", "btn.new_entry", "Catatan Jurnal Baru"),
            Translation::new("ms", "accounting", "btn.post", "Poskan"),
            Translation::new("ms", "accounting", "btn.reverse", "Balikkan"),
            Translation::new("ms", "accounting", "field.journal", "Jurnal"),
            Translation::new("ms", "accounting", "field.debit", "Debit"),
            Translation::new("ms", "accounting", "field.credit", "Kredit"),
            Translation::new("ms", "accounting", "state.draft", "Draf"),
            Translation::new("ms", "accounting", "state.posted", "Telah Dipos"),
            Translation::new("ms", "accounting", "state.cancelled", "Dibatalkan"),
        ]
    }
}
