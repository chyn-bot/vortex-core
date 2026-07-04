//! [`AccountingPlugin`] — the Plugin impl for the accounting base.

use std::sync::Arc;
use std::time::Duration;

use vortex_plugin_sdk::prelude::*;

use crate::{
    handlers, handlers_assets, handlers_banking, handlers_closing, handlers_currency,
    handlers_documents, handlers_einvoice, handlers_tax,
};

const MIG_001_ACCOUNTING: &str = include_str!("../migrations/001_accounting/postgres.sql");
const MIG_002_DOCUMENTS: &str =
    include_str!("../migrations/002_accounting_documents/postgres.sql");
const MIG_003_REGISTRY: &str =
    include_str!("../migrations/003_accounting_registry/postgres.sql");
const MIG_004_MALAYSIAN_TAX: &str =
    include_str!("../migrations/004_malaysian_tax/postgres.sql");
const MIG_005_EINVOICE: &str =
    include_str!("../migrations/005_einvoice/postgres.sql");
const MIG_006_MULTICURRENCY: &str =
    include_str!("../migrations/006_multicurrency/postgres.sql");
const MIG_007_BANKING_ARAP: &str =
    include_str!("../migrations/007_banking_arap/postgres.sql");
const MIG_008_DIMENSIONS_ASSETS: &str =
    include_str!("../migrations/008_dimensions_assets/postgres.sql");
const MIG_009_STATEMENTS_CLOSE: &str =
    include_str!("../migrations/009_statements_close/postgres.sql");

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
        handlers::accounting_routes()
            .merge(handlers_documents::document_routes())
            .merge(handlers_tax::tax_routes())
            .merge(handlers_einvoice::einvoice_routes())
            .merge(handlers_currency::currency_routes())
            .merge(handlers_banking::banking_routes())
            .merge(handlers_assets::asset_routes())
            .merge(handlers_closing::closing_routes())
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
                "accounting.einvoice",
                "e-Invoices",
                "/accounting/einvoice",
                MenuGroup::Operations,
            )
            .under("accounting.moves"),
            MenuEntry::new(
                "accounting.banking",
                "Bank Reconciliation",
                "/accounting/bank-statements",
                MenuGroup::Operations,
            )
            .under("accounting.moves"),
            MenuEntry::new(
                "accounting.pdc",
                "Post-dated Cheques",
                "/accounting/pdc",
                MenuGroup::Operations,
            )
            .under("accounting.moves"),
            MenuEntry::new(
                "accounting.contra",
                "AR/AP Contra",
                "/accounting/contra",
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
            MenuEntry::new(
                "accounting.assets",
                "Fixed Assets",
                "/accounting/assets",
                MenuGroup::Operations,
            )
            .under("accounting.moves"),
            MenuEntry::new(
                "accounting.budgets",
                "Budgets",
                "/accounting/budgets",
                MenuGroup::Operations,
            )
            .under("accounting.moves"),
            MenuEntry::new(
                "accounting.recurring",
                "Recurring Entries",
                "/accounting/recurring",
                MenuGroup::Operations,
            )
            .under("accounting.moves"),
            MenuEntry::new(
                "accounting.config.year_end",
                "Year-End Close",
                "/accounting/year-end",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.config.groups",
                "Statement Groups",
                "/accounting/account-groups",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.config.dimensions",
                "Dimensions",
                "/accounting/dimensions",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.config.taxes",
                "Taxes",
                "/accounting/taxes",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.config.fiscal_years",
                "Fiscal Years",
                "/accounting/fiscal-years",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.config.tax_profiles",
                "Partner Tax Profiles",
                "/accounting/tax-profiles",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.config.rates",
                "Currency Rates",
                "/accounting/currency-rates",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.config.revaluation",
                "FX Revaluation",
                "/accounting/revaluation",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.config.einvoice",
                "e-Invoice (MyInvois)",
                "/accounting/einvoice/settings",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.config.settings",
                "Settings",
                "/accounting/settings",
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
            PluginMigration {
                name: "004_malaysian_tax",
                up_sql: MIG_004_MALAYSIAN_TAX,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "005_einvoice",
                up_sql: MIG_005_EINVOICE,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "006_multicurrency",
                up_sql: MIG_006_MULTICURRENCY,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "007_banking_arap",
                up_sql: MIG_007_BANKING_ARAP,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "008_dimensions_assets",
                up_sql: MIG_008_DIMENSIONS_ASSETS,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "009_statements_close",
                up_sql: MIG_009_STATEMENTS_CLOSE,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
        ]
    }

    /// Daily runs: PDC maturity, due depreciation, recurring entries.
    fn scheduled_actions(&self) -> Vec<ScheduledAction> {
        vec![
            ScheduledAction::new(
                ScheduledActionDef {
                    code: "accounting.pdc.mature",
                    name: "Accounting: clear matured post-dated cheques",
                    schedule: Schedule::Every(Duration::from_secs(24 * 60 * 60)),
                    enabled_by_default: true,
                },
                |state| async move { crate::banking::run_pdc_maturity(&state).await },
            ),
            ScheduledAction::new(
                ScheduledActionDef {
                    code: "accounting.assets.depreciate",
                    name: "Accounting: post due asset depreciation",
                    schedule: Schedule::Every(Duration::from_secs(24 * 60 * 60)),
                    enabled_by_default: true,
                },
                |state| async move { crate::assets::run_depreciation(&state).await },
            ),
            ScheduledAction::new(
                ScheduledActionDef {
                    code: "accounting.recurring.generate",
                    name: "Accounting: generate due recurring entries",
                    schedule: Schedule::Every(Duration::from_secs(24 * 60 * 60)),
                    enabled_by_default: true,
                },
                |state| async move { crate::recurring::run_recurring(&state).await },
            ),
        ]
    }

    fn reports(&self) -> Vec<ReportDef> {
        crate::reports::report_defs()
    }

    /// Durable jobs: MyInvois submit/poll + LHDN code-table sync.
    fn register_jobs(&self, registry: &mut vortex_plugin_sdk::framework::jobs::JobRegistry) {
        crate::einvois::jobs::register(registry);
    }

    /// Contribute the Malaysian tax identity (TIN, BRN/NRIC, SST) to
    /// the contact detail page — contacts stays industry-neutral, the
    /// geography-specific fields ride in from here.
    fn record_panels(&self) -> Vec<RecordPanel> {
        vec![RecordPanel::new(
            RecordPanelDef {
                model: "contacts",
                title: "Tax & e-Invoice Identity (Malaysia)",
                priority: 50,
            },
            |_state, db, contact_id| async move {
                use vortex_plugin_sdk::sqlx::Row;
                let esc = vortex_plugin_sdk::framework::html_escape;
                let row = vortex_plugin_sdk::sqlx::query(
                    "SELECT tin, id_type, id_value, sst_registration, msic_code, \
                            einvoice_email, einvoice_optout \
                     FROM acc_partner_tax_profile WHERE contact_id = $1",
                )
                .bind(contact_id)
                .fetch_optional(&db)
                .await
                .map_err(|e| {
                    vortex_plugin_sdk::common::VortexError::QueryExecution(e.to_string())
                })?;
                let field = |label: &str, value: Option<String>| {
                    format!(
                        "<div><div class=\"text-base-content/50 text-xs\">{}</div>\
                         <div class=\"font-medium\">{}</div></div>",
                        esc(label),
                        esc(value.filter(|v| !v.is_empty()).as_deref().unwrap_or("—")),
                    )
                };
                let body = match &row {
                    Some(r) => {
                        let id_label = format!(
                            "{} No.",
                            r.get::<Option<String>, _>("id_type").as_deref().unwrap_or("BRN/NRIC")
                        );
                        format!(
                            "<div class=\"grid grid-cols-2 md:grid-cols-4 gap-3 text-sm\">{}{}{}{}{}{}</div>",
                            field("TIN", r.get("tin")),
                            field(&id_label, r.get("id_value")),
                            field("SST Registration", r.get("sst_registration")),
                            field("MSIC Code", r.get("msic_code")),
                            field("e-Invoice Email", r.get("einvoice_email")),
                            field(
                                "e-Invoice",
                                Some(
                                    if r.get::<bool, _>("einvoice_optout") {
                                        "consolidated only".to_string()
                                    } else {
                                        "individual".to_string()
                                    },
                                ),
                            ),
                        )
                    }
                    None => "<p class=\"text-sm opacity-60\">No tax profile yet — required for \
                             MyInvois e-invoicing and SST reporting.</p>"
                        .to_string(),
                };
                Ok(format!(
                    "{body}<div class=\"mt-3\"><a href=\"/accounting/tax-profiles/by-contact/{contact_id}\" \
                     class=\"btn btn-sm btn-outline\">{} Tax Profile</a></div>",
                    if row.is_some() { "Edit" } else { "Create" },
                ))
            },
        )]
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
