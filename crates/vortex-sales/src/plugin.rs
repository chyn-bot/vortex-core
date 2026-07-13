//! [`SalesPlugin`] — the Plugin impl for order-to-cash.

use std::sync::Arc;

use std::time::Duration;

use vortex_plugin_sdk::prelude::*;

use crate::handlers;

const MIG_001_SALES: &str = include_str!("../migrations/001_sales/postgres.sql");
const MIG_002_REGISTRY: &str = include_str!("../migrations/002_sales_registry/postgres.sql");
const MIG_003_DELIVERY: &str = include_str!("../migrations/003_delivery_docs/postgres.sql");
const MIG_004_QUOTATIONS: &str = include_str!("../migrations/004_quotations/postgres.sql");
const MIG_005_DESC_TEXT: &str = include_str!("../migrations/005_line_description_text/postgres.sql");
const MIG_006_QUOTE_FIELDS: &str = include_str!("../migrations/006_quote_fields/postgres.sql");
const MIG_007_DISPLAY_TYPE: &str = include_str!("../migrations/007_line_display_type/postgres.sql");
const MIG_008_QUOTE_DISCOUNT: &str = include_str!("../migrations/008_quote_discount/postgres.sql");
const MIG_009_LINE_UOM: &str = include_str!("../migrations/009_line_uom/postgres.sql");
const MIG_010_NOTE_TEMPLATES: &str = include_str!("../migrations/010_note_templates/postgres.sql");
const MIG_011_PAYMENT_TERM: &str = include_str!("../migrations/011_payment_term/postgres.sql");
const MIG_012_LIST_URL: &str = include_str!("../migrations/012_list_url/postgres.sql");

pub struct SalesPlugin;

impl SalesPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SalesPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for SalesPlugin {
    fn technical_name(&self) -> &'static str {
        "sales"
    }

    /// Sales models projected into the metadata registry from their
    /// `#[derive(Model)]` structs — supersedes migration `002_sales_registry`.
    fn models(&self) -> Vec<&'static vortex_orm::model::ModelMeta> {
        use vortex_orm::model::Model;
        vec![crate::model::SalesOrder::meta()]
    }

    fn display_name(&self) -> &'static str {
        "Sales"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn summary(&self) -> &'static str {
        "Customers, sales orders, deliveries and the invoice bridge"
    }

    fn description(&self) -> &'static str {
        "Order-to-cash on top of the platform primitives. Raise and confirm sales \
         orders for customers (core contacts), deliver goods out of inventory via \
         the stock ledger, and bridge the order into an accounting customer \
         invoice carrying real taxes and LHDN e-invoice classifications — lines \
         default from the product master."
    }

    fn author(&self) -> &'static str {
        "Vortex Core"
    }

    fn category(&self) -> &'static str {
        "Sales"
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["inventory", "accounting"]
    }

    fn routes(&self) -> Router<Arc<AppState>> {
        handlers::sales_routes()
    }

    /// The quotation is user-customisable in Settings ▸ Print Templates.
    fn print_docs(&self) -> Vec<PrintDocType> {
        vec![handlers::quotation_print_doc()]
    }

    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![
            MenuEntry::new("sales.quotes", "Quotations", "/sales/quotes", MenuGroup::Operations)
                .with_icon("cart")
                .with_priority(37),
            MenuEntry::new("sales.orders", "Sales Orders", "/sales", MenuGroup::Operations)
                .with_icon("cart")
                .with_priority(38),
            // Configuration — collapsible parent, Odoo-style.
            MenuEntry::new("sales.config", "Configuration", "#", MenuGroup::Operations)
                .with_icon("cog")
                .with_priority(95),
            MenuEntry::new(
                "sales.note_templates",
                "Terms Templates",
                "/sales/note-templates",
                MenuGroup::Operations,
            )
            .with_icon("file-text")
            .with_priority(96)
            .under("sales.config"),
        ]
    }

    /// Plugin-owned migrations. Registration order guarantees the
    /// referenced accounting + inventory tables exist.
    fn migrations(&self) -> Vec<PluginMigration> {
        vec![
            PluginMigration {
                name: "001_sales",
                up_sql: MIG_001_SALES,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "002_sales_registry",
                up_sql: MIG_002_REGISTRY,
                down_sql: None,
                requires_core_migration: Some("122_model_registry"),
            },
            PluginMigration {
                name: "003_delivery_docs",
                up_sql: MIG_003_DELIVERY,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "004_quotations",
                up_sql: MIG_004_QUOTATIONS,
                down_sql: None,
                requires_core_migration: Some("122_model_registry"),
            },
            PluginMigration {
                name: "005_line_description_text",
                up_sql: MIG_005_DESC_TEXT,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "006_quote_fields",
                up_sql: MIG_006_QUOTE_FIELDS,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "007_line_display_type",
                up_sql: MIG_007_DISPLAY_TYPE,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "008_quote_discount",
                up_sql: MIG_008_QUOTE_DISCOUNT,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "009_line_uom",
                up_sql: MIG_009_LINE_UOM,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "010_note_templates",
                up_sql: MIG_010_NOTE_TEMPLATES,
                down_sql: None,
                requires_core_migration: None,
            },
            // References the accounting-owned `payment_term` table (accounting
            // migration 016); accounting registers before sales.
            PluginMigration {
                name: "011_payment_term",
                up_sql: MIG_011_PAYMENT_TERM,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "012_list_url",
                up_sql: MIG_012_LIST_URL,
                down_sql: None,
                requires_core_migration: Some("123_model_list_url"),
            },
        ]
    }

    /// Daily sweep: a sent quotation past its validity date expires.
    /// (Revise re-opens it as a new revision.)
    fn scheduled_actions(&self) -> Vec<ScheduledAction> {
        vec![ScheduledAction::new(
            ScheduledActionDef {
                code: "sales.expire_quotations",
                name: "Sales: expire overdue quotations",
                schedule: Schedule::Every(Duration::from_secs(24 * 60 * 60)),
                enabled_by_default: true,
            },
            |state| async move {
                let n = vortex_plugin_sdk::sqlx::query(
                    "UPDATE sales_order SET state = 'expired', updated_at = NOW() \
                     WHERE state = 'sent' AND validity_date IS NOT NULL \
                       AND validity_date < CURRENT_DATE",
                )
                .execute(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?
                .rows_affected();
                if n > 0 {
                    vortex_plugin_sdk::tracing::info!(count = n, "quotations expired");
                }
                Ok(())
            },
        )]
    }

    fn translations(&self) -> Vec<Translation> {
        vec![
            Translation::new("en", "sales", "menu.title", "Sales"),
            Translation::new("en", "sales", "menu.orders", "Sales Orders"),
            Translation::new("en", "sales", "btn.new_order", "New Sales Order"),
            Translation::new("ms", "sales", "menu.title", "Jualan"),
            Translation::new("ms", "sales", "menu.orders", "Pesanan Jualan"),
            Translation::new("ms", "sales", "btn.new_order", "Pesanan Jualan Baru"),
        ]
    }
}
