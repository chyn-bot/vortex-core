//! [`IwkPlugin`] — the Plugin impl. Everything is declarative:
//! state what you have, the host wires it.

use std::sync::Arc;
use std::time::Duration;

use vortex_plugin_sdk::prelude::*;

use crate::{billing, handlers};

const MIG_001_INIT: &str = include_str!("../migrations/001_init/postgres.sql");
const MIG_002_GL: &str = include_str!("../migrations/002_gl/postgres.sql");
const MIG_003_CONTRACTS: &str = include_str!("../migrations/003_contracts/postgres.sql");
const MIG_004_PAYMENTS: &str = include_str!("../migrations/004_payments/postgres.sql");

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
            MenuEntry::new("iwk.contracts", "Contracts", "/iwk/accounts", MenuGroup::Operations)
                .with_icon("clipboard-list")
                .with_priority(47),
            MenuEntry::new("iwk.register", "Register Customer", "/iwk/accounts/new", MenuGroup::Operations)
                .with_icon("user-plus")
                .with_priority(48),
            MenuEntry::new("iwk.billing", "Generate Bills", "/iwk/billing", MenuGroup::Operations)
                .with_icon("refresh-cw")
                .with_priority(49),
            MenuEntry::new("iwk.bills", "IWK Bills", "/iwk", MenuGroup::Operations)
                .with_icon("file-text")
                .with_priority(50),
            MenuEntry::new("iwk.payments", "Payments", "/iwk/payments", MenuGroup::Operations)
                .with_icon("credit-card")
                .with_priority(50),
            MenuEntry::new("iwk.gl", "GL & Reconciliation", "/iwk/gl", MenuGroup::Operations)
                .with_icon("book-open")
                .with_priority(51),
        ]
    }

    /// Recurring billing. Disabled by default: enabling it starts generating
    /// bills for every contract whose cycle is due, which is a financial
    /// action operators should switch on deliberately (the /iwk/billing page
    /// gives the same generator on a manual trigger meanwhile).
    fn scheduled_actions(&self) -> Vec<ScheduledAction> {
        vec![ScheduledAction::new(
            ScheduledActionDef {
                code: "iwk.generate_due_bills",
                name: "IWK: generate bills for contracts due today",
                schedule: Schedule::Every(Duration::from_secs(24 * 60 * 60)),
                enabled_by_default: false,
            },
            |state| async move {
                let today = chrono::Utc::now().date_naive();
                billing::generate_bills_for_period(&state.db, today)
                    .await
                    .map(|_| ())
                    .map_err(vortex_plugin_sdk::common::VortexError::QueryExecution)
            },
        )]
    }

    /// Cross-plugin card on the contact record: the customer's sewerage
    /// accounts + billed/paid/outstanding + a link to their full ledger.
    /// Returns "" (no card) for contacts that aren't IWK customers.
    fn record_panels(&self) -> Vec<RecordPanel> {
        vec![RecordPanel::new(
            RecordPanelDef { model: "contacts", title: "Sewerage Accounts (IWK)", priority: 40 },
            |_state, db, contact_id| async move {
                crate::ledger::contact_panel(&db, contact_id)
                    .await
                    .map_err(vortex_plugin_sdk::common::VortexError::QueryExecution)
            },
        )]
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
            PluginMigration {
                // Contract lifecycle on iwk_account (status, cycle, next_bill
                // cursor) + number sequences for the recurring generator.
                name: "003_contracts",
                up_sql: MIG_003_CONTRACTS,
                down_sql: None,
                requires_core_migration: Some("124_record_stages"),
            },
            PluginMigration {
                // Payment subledger + allocation + Customer Advances account +
                // summarized collection-posting ledger.
                name: "004_payments",
                up_sql: MIG_004_PAYMENTS,
                down_sql: None,
                requires_core_migration: Some("124_record_stages"),
            },
        ]
    }
}
