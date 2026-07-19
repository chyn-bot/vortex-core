//! [`AccountingPlugin`] — the Plugin impl for the accounting base.

use std::sync::Arc;
use std::time::Duration;

use vortex_plugin_sdk::prelude::*;

use crate::{
    handlers, handlers_assets, handlers_banking, handlers_closing, handlers_currency,
    handlers_documents, handlers_einvoice, handlers_payment_terms, handlers_tax,
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
const MIG_010_PARTNER_ACCOUNTS: &str =
    include_str!("../migrations/010_partner_accounts/postgres.sql");
const MIG_011_PARTNER_BANKS: &str =
    include_str!("../migrations/011_partner_banks/postgres.sql");
const MIG_012_BANK_MASTER: &str =
    include_str!("../migrations/012_bank_master/postgres.sql");
const MIG_013_CLASSIFICATION_CODES: &str =
    include_str!("../migrations/013_classification_codes/postgres.sql");
const MIG_014_UNPOST: &str = include_str!("../migrations/014_unpost/postgres.sql");
const MIG_015_LINE_PRODUCT: &str =
    include_str!("../migrations/015_line_product/postgres.sql");
const MIG_016_PAYMENT_TERMS: &str =
    include_str!("../migrations/016_payment_terms/postgres.sql");
const MIG_017_SCALE_INDEXES: &str =
    include_str!("../migrations/017_scale_indexes/postgres.sql");

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

    /// Accounting models projected into the metadata registry from their
    /// `#[derive(Model)]` structs — supersedes migration `003_accounting_registry`.
    fn models(&self) -> Vec<&'static vortex_orm::model::ModelMeta> {
        use vortex_orm::model::Model;
        vec![
            crate::model::AccMove::meta(),
            crate::model::AccAccount::meta(),
        ]
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
            .merge(handlers_payment_terms::payment_term_routes())
    }

    /// Menu mirrors the sub-ledger mental model (AutoCount/SQL style):
    /// Receivables / Payables / Banking / General Ledger / Setup —
    /// not one flat "Journal Entries" bucket.
    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![
            // ── Receivables (AR) ────────────────────────────────
            MenuEntry::new(
                "accounting.ar",
                "Receivables",
                "/accounting/invoices",
                MenuGroup::Operations,
            )
            .with_priority(40),
            MenuEntry::new(
                "accounting.ar.invoices",
                "Customer Invoices",
                "/accounting/invoices",
                MenuGroup::Operations,
            )
            .under("accounting.ar"),
            MenuEntry::new(
                "accounting.ar.einvoice",
                "e-Invoice Queue (LHDN)",
                "/accounting/einvoice",
                MenuGroup::Operations,
            )
            .under("accounting.ar"),
            MenuEntry::new(
                "accounting.ar.statement",
                "Statement of Account",
                "/accounting/statement",
                MenuGroup::Operations,
            )
            .under("accounting.ar"),
            // ── Payables (AP) ───────────────────────────────────
            MenuEntry::new(
                "accounting.ap",
                "Payables",
                "/accounting/bills",
                MenuGroup::Operations,
            )
            .with_priority(41),
            MenuEntry::new(
                "accounting.ap.bills",
                "Vendor Bills",
                "/accounting/bills",
                MenuGroup::Operations,
            )
            .under("accounting.ap"),
            MenuEntry::new(
                "accounting.ap.contra",
                "AR/AP Contra",
                "/accounting/contra",
                MenuGroup::Operations,
            )
            .under("accounting.ap"),
            // ── Banking ─────────────────────────────────────────
            MenuEntry::new(
                "accounting.bank",
                "Banking",
                "/accounting/payments",
                MenuGroup::Operations,
            )
            .with_priority(42),
            MenuEntry::new(
                "accounting.bank.payments",
                "Receipts & Payments",
                "/accounting/payments",
                MenuGroup::Operations,
            )
            .under("accounting.bank"),
            MenuEntry::new(
                "accounting.bank.recon",
                "Bank Reconciliation",
                "/accounting/bank-statements",
                MenuGroup::Operations,
            )
            .under("accounting.bank"),
            MenuEntry::new(
                "accounting.bank.pdc",
                "Post-dated Cheques",
                "/accounting/pdc",
                MenuGroup::Operations,
            )
            .under("accounting.bank"),
            // ── General Ledger ──────────────────────────────────
            MenuEntry::new(
                "accounting.gl",
                "General Ledger",
                "/accounting",
                MenuGroup::Operations,
            )
            .with_icon("scale")
            .with_priority(43),
            MenuEntry::new(
                "accounting.gl.moves",
                "Journal Entries",
                "/accounting",
                MenuGroup::Operations,
            )
            .under("accounting.gl"),
            MenuEntry::new(
                "accounting.config",
                "Accounting Setup",
                "/accounting/accounts",
                MenuGroup::Operations,
            )
            .with_icon("settings")
            .with_priority(45),
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
                "accounting.config.payment_terms",
                "Payment Terms",
                "/accounting/payment-terms",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.gl.recurring",
                "Recurring Entries",
                "/accounting/recurring",
                MenuGroup::Operations,
            )
            .under("accounting.gl"),
            MenuEntry::new(
                "accounting.gl.budgets",
                "Budgets",
                "/accounting/budgets",
                MenuGroup::Operations,
            )
            .under("accounting.gl"),
            MenuEntry::new(
                "accounting.gl.assets",
                "Fixed Assets",
                "/accounting/assets",
                MenuGroup::Operations,
            )
            .under("accounting.gl"),
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
                "accounting.config.lhdn_codes",
                "LHDN Catalogues",
                "/accounting/lhdn-codes",
                MenuGroup::Operations,
            )
            .under("accounting.config"),
            MenuEntry::new(
                "accounting.config.banks",
                "Banks",
                "/accounting/banks",
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
            PluginMigration {
                name: "010_partner_accounts",
                up_sql: MIG_010_PARTNER_ACCOUNTS,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "011_partner_banks",
                up_sql: MIG_011_PARTNER_BANKS,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "012_bank_master",
                up_sql: MIG_012_BANK_MASTER,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "013_classification_codes",
                up_sql: MIG_013_CLASSIFICATION_CODES,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "014_unpost",
                up_sql: MIG_014_UNPOST,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "015_line_product",
                up_sql: MIG_015_LINE_PRODUCT,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "016_payment_terms",
                up_sql: MIG_016_PAYMENT_TERMS,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "017_scale_indexes",
                up_sql: MIG_017_SCALE_INDEXES,
                down_sql: Some(
                    "DROP INDEX IF EXISTS idx_acc_move_movedate_id; \
                     DROP INDEX IF EXISTS idx_acc_move_type_invdate_id; \
                     DROP INDEX IF EXISTS idx_acc_move_number_trgm; \
                     DROP INDEX IF EXISTS idx_acc_move_ref_trgm;",
                ),
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
                    code: "accounting.fx.bnm_rates",
                    name: "Accounting: sync BNM exchange rates",
                    schedule: Schedule::Every(Duration::from_secs(12 * 60 * 60)),
                    enabled_by_default: true,
                },
                |state| async move { crate::bnm::run_bnm_sync(&state).await },
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

    /// Durable jobs: MyInvois submit/poll + LHDN code-table sync +
    /// email-document-with-PDF.
    fn register_jobs(&self, registry: &mut vortex_plugin_sdk::framework::jobs::JobRegistry) {
        crate::einvois::jobs::register(registry);
        crate::doc_email::register(registry);
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
                         form=\"record-form\" class=\"input input-bordered input-sm w-full\"/></label>",
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
<select name="id_type" form="record-form" class="select select-bordered select-sm w-full">
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
                    msic = {
                        // Searchable over the synced LHDN MSIC catalogue.
                        let opts: String = crate::handlers_tax::msic_lookup(&db)
                            .await
                            .iter()
                            .map(|(code, label)| {
                                format!(
                                    "<option value=\"{}\">{}</option>",
                                    esc(code),
                                    esc(label)
                                )
                            })
                            .collect();
                        format!(
                            "<label class=\"form-control\"><span class=\"label-text text-xs mb-1\">MSIC Code</span>\
                             <input name=\"msic_code\" value=\"{}\" placeholder=\"62010\" list=\"dl-panel-msic\" \
                             form=\"record-form\" class=\"input input-bordered input-sm w-full\"/>\
                             <datalist id=\"dl-panel-msic\">{opts}</datalist></label>",
                            val("msic_code"),
                        )
                    },
                    email = text_input("einvoice_email", "e-Invoice Email", val("einvoice_email"), ""),
                    sel_brn = sel("BRN"),
                    sel_nric = sel("NRIC"),
                    sel_pass = sel("PASSPORT"),
                    sel_army = sel("ARMY"),
                    optout_checked = if optout { " checked" } else { "" },
                ))
            },
        )
        .with_save(|state, db, contact_id, pairs, ctx| async move {
            // Only act on submissions that actually carried the panel
            // (the hidden __acc_tax_panel marker) — other contact
            // update paths must not blank the tax fields.
            if !pairs.iter().any(|(k, _)| k == "__acc_tax_panel") {
                return Ok(());
            }
            use vortex_plugin_sdk::sqlx::Row;
            // Snapshot → save → diff, so the CONTACT's history shows
            // exactly which tax fields changed (same entry shape the
            // field tracker writes).
            const FIELDS: [(&str, &str); 10] = [
                ("tin", "TIN"),
                ("id_type", "ID Type"),
                ("id_value", "BRN/NRIC No."),
                ("sst_registration", "SST Registration"),
                ("msic_code", "MSIC Code"),
                ("einvoice_email", "e-Invoice Email"),
                ("einvoice_optout", "Consolidated e-Invoice Only"),
                ("receivable_account", "Receivable Account"),
                ("payable_account", "Payable Account"),
                ("payment_term", "Payment Terms"),
            ];
            let snapshot = |row: Option<&vortex_plugin_sdk::sqlx::postgres::PgRow>| {
                FIELDS
                    .iter()
                    .map(|(col, _)| {
                        let v = match *col {
                            "einvoice_optout" => row
                                .map(|r| r.get::<bool, _>("einvoice_optout"))
                                .unwrap_or(false)
                                .then_some("Yes".to_string())
                                .unwrap_or_else(|| "No".to_string()),
                            _ => row
                                .and_then(|r| r.get::<Option<String>, _>(*col))
                                .unwrap_or_default(),
                        };
                        v
                    })
                    .collect::<Vec<String>>()
            };
            let select = "SELECT p.tin, p.id_type, p.id_value, p.sst_registration, p.msic_code, \
                          p.einvoice_email, p.einvoice_optout, \
                          COALESCE(ar.code || ' ' || ar.name, '') AS receivable_account, \
                          COALESCE(ap.code || ' ' || ap.name, '') AS payable_account, \
                          COALESCE(pt.name, '') AS payment_term \
                          FROM acc_partner_tax_profile p \
                          LEFT JOIN acc_account ar ON ar.id = p.receivable_account_id \
                          LEFT JOIN acc_account ap ON ap.id = p.payable_account_id \
                          LEFT JOIN payment_term pt ON pt.id = p.payment_term_id \
                          WHERE p.contact_id = $1";
            let before_row = vortex_plugin_sdk::sqlx::query(select)
                .bind(contact_id)
                .fetch_optional(&db)
                .await
                .map_err(|e| {
                    vortex_plugin_sdk::common::VortexError::QueryExecution(e.to_string())
                })?;
            let before = snapshot(before_row.as_ref());
            crate::handlers_tax::upsert_profile_fields(&db, contact_id, &pairs)
                .await
                .map_err(vortex_plugin_sdk::common::VortexError::ValidationFailed)?;
            let after_row = vortex_plugin_sdk::sqlx::query(select)
                .bind(contact_id)
                .fetch_optional(&db)
                .await
                .map_err(|e| {
                    vortex_plugin_sdk::common::VortexError::QueryExecution(e.to_string())
                })?;
            let after = snapshot(after_row.as_ref());
            let changes: Vec<vortex_plugin_sdk::serde_json::Value> = FIELDS
                .iter()
                .zip(before.iter().zip(after.iter()))
                .filter(|(_, (b, a))| b != a)
                .map(|((_, label), (b, a))| {
                    vortex_plugin_sdk::serde_json::json!({
                        "field": format!("{label} (tax)"),
                        "from": b,
                        "to": a,
                    })
                })
                .collect();
            if !changes.is_empty() {
                let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
                    .with_user(UserId(ctx.user_id))
                    .with_username(&ctx.username)
                    .with_database(&ctx.db_name)
                    .with_resource("contact", contact_id.to_string())
                    .with_details(vortex_plugin_sdk::serde_json::json!({ "changes": changes }));
                if let Err(e) = state.audit.log(entry).await {
                    vortex_plugin_sdk::tracing::error!("tax panel audit write failed: {e}");
                }
            }
            Ok(())
        }),
        RecordPanel::new(
            RecordPanelDef {
                model: "contacts",
                title: "Accounting",
                priority: 60,
            },
            |_state, db, contact_id| async move {
                use vortex_plugin_sdk::sqlx::Row;
                let esc = vortex_plugin_sdk::framework::html_escape;
                // Control-account overrides (saved by the single Save
                // via the tax panel's hook — same record-form).
                let profile = vortex_plugin_sdk::sqlx::query(
                    "SELECT receivable_account_id, payable_account_id, payment_term_id \
                     FROM acc_partner_tax_profile WHERE contact_id = $1",
                )
                .bind(contact_id)
                .fetch_optional(&db)
                .await
                .map_err(|e| {
                    vortex_plugin_sdk::common::VortexError::QueryExecution(e.to_string())
                })?;
                let selected = |col: &str| {
                    profile
                        .as_ref()
                        .and_then(|r| r.get::<Option<vortex_plugin_sdk::uuid::Uuid>, _>(col))
                };
                let load_accounts = |t: &'static str| {
                    let db = db.clone();
                    async move {
                        vortex_plugin_sdk::sqlx::query(
                            "SELECT id, code, name FROM acc_account \
                             WHERE active AND reconcile AND account_type = $1 ORDER BY code",
                        )
                        .bind(t)
                        .fetch_all(&db)
                        .await
                        .unwrap_or_default()
                        .iter()
                        .map(|r| {
                            (
                                r.get::<vortex_plugin_sdk::uuid::Uuid, _>("id"),
                                r.get::<String, _>("code"),
                                r.get::<String, _>("name"),
                            )
                        })
                        .collect::<Vec<_>>()
                    }
                };
                let account_select =
                    |name: &str,
                     label: &str,
                     sel: Option<vortex_plugin_sdk::uuid::Uuid>,
                     accounts: &[(vortex_plugin_sdk::uuid::Uuid, String, String)]| {
                        let mut opts = String::from("<option value=\"\">Company default</option>");
                        for (id, code, aname) in accounts {
                            let s = if sel == Some(*id) { " selected" } else { "" };
                            opts.push_str(&format!(
                                "<option value=\"{id}\"{s}>{} {}</option>",
                                esc(code),
                                esc(aname),
                            ));
                        }
                        // Account names are long — each picker takes
                        // half the 4-column row.
                        format!(
                            "<label class=\"form-control col-span-2\"><span class=\"label-text text-xs mb-1\">{}</span>\
                             <select name=\"{name}\" form=\"record-form\" class=\"select select-bordered select-sm w-full\">{opts}</select></label>",
                            esc(label),
                        )
                    };
                let ar = account_select(
                    "receivable_account_id",
                    "Receivable Account (control)",
                    selected("receivable_account_id"),
                    &load_accounts("asset_receivable").await,
                );
                let ap = account_select(
                    "payable_account_id",
                    "Payable Account (control)",
                    selected("payable_account_id"),
                    &load_accounts("liability_payable").await,
                );

                // Default payment terms — pre-fills new quotations for this
                // partner. Options come from Accounting Setup ▸ Payment Terms.
                let pt_opts = handlers_payment_terms::payment_term_options(
                    &db,
                    selected("payment_term_id"),
                )
                .await;

                // Bank accounts list + add row. The bank itself comes
                // from the user-configurable master (Setup ▸ Banks).
                let bank_options: String = vortex_plugin_sdk::sqlx::query(
                    "SELECT id, name FROM acc_bank WHERE active ORDER BY name",
                )
                .fetch_all(&db)
                .await
                .unwrap_or_default()
                .iter()
                .map(|r| {
                    format!(
                        "<option value=\"{}\">{}</option>",
                        r.get::<vortex_plugin_sdk::uuid::Uuid, _>("id"),
                        esc(&r.get::<String, _>("name")),
                    )
                })
                .collect();
                let banks = vortex_plugin_sdk::sqlx::query(
                    "SELECT id, bank_name, account_number, account_holder, swift_code \
                     FROM acc_partner_bank WHERE contact_id = $1 ORDER BY created_at",
                )
                .bind(contact_id)
                .fetch_all(&db)
                .await
                .unwrap_or_default();
                let mut bank_rows = String::new();
                for b in &banks {
                    let bid: vortex_plugin_sdk::uuid::Uuid = b.get("id");
                    bank_rows.push_str(&format!(
                        "<tr><td>{}</td><td class=\"font-mono\">{}</td><td>{}</td><td>{}</td>\
                         <td><button form=\"record-form\" formmethod=\"post\" \
                         formaction=\"/accounting/partner-banks/{bid}/delete\" \
                         class=\"btn btn-xs btn-ghost text-error\" \
                         onclick=\"return confirm('Remove this bank account?')\">✕</button></td></tr>",
                        esc(&b.get::<String, _>("bank_name")),
                        esc(&b.get::<String, _>("account_number")),
                        esc(b.get::<Option<String>, _>("account_holder").as_deref().unwrap_or("—")),
                        esc(b.get::<Option<String>, _>("swift_code").as_deref().unwrap_or("—")),
                    ));
                }
                let bank_table = if banks.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<table class=\"table table-sm mt-3\"><thead><tr><th>Bank</th>\
                         <th>Account No.</th><th>Holder</th><th>SWIFT</th><th></th></tr></thead>\
                         <tbody>{bank_rows}</tbody></table>"
                    )
                };
                Ok(format!(
                    r#"<div class="grid grid-cols-2 md:grid-cols-4 gap-3">
<label class="form-control col-span-2"><span class="label-text text-xs mb-1">Default Payment Terms</span>
<select name="payment_term_id" form="record-form" class="select select-bordered select-sm w-full">{pt_opts}</select></label>
</div>
<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">{ar}{ap}</div>
<div class="divider text-xs opacity-60 my-2">Bank Accounts</div>
{bank_table}
<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mt-2 items-end">
<label class="form-control"><span class="label-text text-xs mb-1">Bank</span>
<select name="bank_id" form="record-form" class="select select-bordered select-sm w-full">
<option value="">-- Select bank --</option>{bank_options}</select></label>
<label class="form-control"><span class="label-text text-xs mb-1">Account No.</span>
<input name="bank_account_number" form="record-form" inputmode="numeric" placeholder="512345678901" class="input input-bordered input-sm w-full"/></label>
<label class="form-control"><span class="label-text text-xs mb-1">Holder</span>
<input name="bank_account_holder" form="record-form" class="input input-bordered input-sm w-full"/></label>
<button form="record-form" formmethod="post" formaction="/accounting/partner-banks/{contact_id}/add" class="btn btn-sm btn-outline" title="Also saves the accounting fields above">Add Bank Account</button>
</div>
<p class="text-xs opacity-50 mt-1">SWIFT fills in from the bank master — manage the list under Accounting Setup ▸ Banks.</p>"#,
                ))
            },
        ),
        RecordPanel::new(
            RecordPanelDef {
                model: "contacts",
                title: "Statement of Account",
                priority: 70,
            },
            |_state, db, contact_id| async move {
                // Net posted AR/AP balance for this partner (debit − credit):
                // positive = a customer owes us, negative = we owe a vendor.
                let bal: vortex_plugin_sdk::rust_decimal::Decimal =
                    vortex_plugin_sdk::sqlx::query_scalar(
                        "SELECT COALESCE(SUM(l.debit - l.credit), 0) FROM acc_move_line l \
                         JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted' \
                         JOIN acc_account a ON a.id = l.account_id \
                         WHERE l.partner_id = $1 \
                           AND a.account_type IN ('asset_receivable', 'liability_payable')",
                    )
                    .bind(contact_id)
                    .fetch_one(&db)
                    .await
                    .unwrap_or_default();
                let zero = vortex_plugin_sdk::rust_decimal::Decimal::ZERO;
                let hint = if bal > zero {
                    "owed to you (receivable)"
                } else if bal < zero {
                    "you owe (payable)"
                } else {
                    "nothing outstanding"
                };
                Ok(format!(
                    r#"<div class="flex items-center justify-between flex-wrap gap-3">
<div><div class="text-2xl font-bold font-mono">{bal:.2}</div><div class="text-xs opacity-60">Outstanding balance — {hint}</div></div>
<div class="flex gap-2">
<a href="/reports/accounting.statement_of_account?partner={cid}" target="_blank" class="btn btn-sm btn-primary">View statement</a>
{pdf}
<a href="/reports/accounting.statement_of_account?partner={cid}&amp;format=csv" class="btn btn-sm btn-outline">CSV</a>
<a href="/accounting/statement?partner={cid}" class="btn btn-sm btn-ghost">Date range…</a>
</div>
</div>"#,
                    bal = bal,
                    hint = hint,
                    cid = contact_id,
                    pdf = if vortex_plugin_sdk::framework::pdf::available() {
                        format!(
                            r#"<a href="/accounting/statement/pdf?partner={cid}" class="btn btn-sm btn-outline">PDF</a>"#,
                            cid = contact_id,
                        )
                    } else {
                        String::new()
                    },
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
