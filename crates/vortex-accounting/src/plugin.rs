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
                // Inline editable — saving stays on the contact page.
                let val = |k: &str| -> String {
                    row.as_ref()
                        .and_then(|r| r.get::<Option<String>, _>(k))
                        .map(|v| esc(&v))
                        .unwrap_or_default()
                };
                let id_type = row
                    .as_ref()
                    .and_then(|r| r.get::<Option<String>, _>("id_type"))
                    .unwrap_or_default();
                let optout = row.as_ref().map(|r| r.get::<bool, _>("einvoice_optout")).unwrap_or(false);
                let sel = |v: &str| if id_type == v { " selected" } else { "" };
                let text_input = |name: &str, label: &str, value: String, placeholder: &str| {
                    format!(
                        "<label class=\"form-control\"><span class=\"label-text text-xs mb-1\">{}</span>\
                         <input name=\"{name}\" value=\"{value}\" placeholder=\"{placeholder}\" \
                         form=\"record-form\" class=\"input input-bordered input-sm\"/></label>",
                        esc(label),
                    )
                };
                // The inputs join the contact page's own <form> via
                // form="record-form" — its single Save button persists
                // contact + tax fields together (the with_save hook
                // below receives the submission). The hidden marker
                // keeps other update paths from blanking the fields.
                Ok(format!(
                    r#"<input type="hidden" name="__acc_tax_panel" value="1" form="record-form"/>
<div class="grid grid-cols-2 md:grid-cols-4 gap-3">
{tin}
<label class="form-control"><span class="label-text text-xs mb-1">ID Type</span>
<select name="id_type" form="record-form" class="select select-bordered select-sm">
<option value="BRN"{sel_brn}>BRN — Business Reg.</option>
<option value="NRIC"{sel_nric}>NRIC</option>
<option value="PASSPORT"{sel_pass}>Passport</option>
<option value="ARMY"{sel_army}>Army ID</option>
</select></label>
{id_value}{sst}{msic}{email}
<label class="label cursor-pointer justify-start gap-2 mt-5">
<input type="checkbox" name="einvoice_optout" form="record-form" class="checkbox checkbox-sm"{optout_checked}/>
<span class="label-text text-xs">Consolidated e-invoice only</span></label>
</div>
<div class="flex gap-2 mt-3">
<button form="record-form" formaction="/accounting/tax-profiles/by-contact/{contact_id}/search-tin" formmethod="post" class="btn btn-sm btn-outline" title="Saves the tax fields, then looks up the TIN at LHDN by the ID type + value">Search TIN (LHDN)</button>
<a href="/accounting/tax-profiles/by-contact/{contact_id}" class="btn btn-sm btn-ghost">Full profile &amp; TIN validation</a>
</div>"#,
                    tin = text_input("tin", "TIN", val("tin"), "C1234567890 / IG12345678901"),
                    id_value = text_input("id_value", "BRN / NRIC No.", val("id_value"), "201901012345"),
                    sst = text_input("sst_registration", "SST Registration", val("sst_registration"), ""),
                    msic = text_input("msic_code", "MSIC Code", val("msic_code"), "62010"),
                    email = text_input("einvoice_email", "e-Invoice Email", val("einvoice_email"), ""),
                    sel_brn = sel("BRN"),
                    sel_nric = sel("NRIC"),
                    sel_pass = sel("PASSPORT"),
                    sel_army = sel("ARMY"),
                    optout_checked = if optout { " checked" } else { "" },
                ))
            },
        )
        .with_save(|_state, db, contact_id, pairs| async move {
            // Only act on submissions that actually carried the panel
            // (the hidden __acc_tax_panel marker) — other contact
            // update paths must not blank the tax fields.
            if !pairs.iter().any(|(k, _)| k == "__acc_tax_panel") {
                return Ok(());
            }
            crate::handlers_tax::upsert_profile_fields(&db, contact_id, &pairs)
                .await
                .map(|_| ())
                .map_err(vortex_plugin_sdk::common::VortexError::ValidationFailed)
        })]
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
