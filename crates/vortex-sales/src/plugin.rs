//! [`SalesPlugin`] — the Plugin impl for order-to-cash.

use std::sync::Arc;

use std::time::Duration;

use vortex_plugin_sdk::prelude::*;

use crate::handlers;

const MIG_001_SALES: &str = include_str!("../migrations/001_sales/postgres.sql");
const MIG_002_REGISTRY: &str = include_str!("../migrations/002_sales_registry/postgres.sql");
const MIG_003_DELIVERY: &str = include_str!("../migrations/003_delivery_docs/postgres.sql");
const MIG_004_QUOTATIONS: &str = include_str!("../migrations/004_quotations/postgres.sql");

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

    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![
            MenuEntry::new("sales.quotes", "Quotations", "/sales/quotes", MenuGroup::Operations)
                .with_icon("cart")
                .with_priority(37),
            MenuEntry::new("sales.orders", "Sales Orders", "/sales", MenuGroup::Operations)
                .with_icon("cart")
                .with_priority(38),
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
