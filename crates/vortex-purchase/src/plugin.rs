//! [`PurchasePlugin`] — the Plugin impl for procurement.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;

use crate::handlers;

const MIG_001_PURCHASE: &str = include_str!("../migrations/001_purchase/postgres.sql");
const MIG_002_REGISTRY: &str = include_str!("../migrations/002_purchase_registry/postgres.sql");
const MIG_003_VENDOR_BILL: &str = include_str!("../migrations/003_vendor_bill/postgres.sql");
const MIG_004_RFQ: &str = include_str!("../migrations/004_rfq/postgres.sql");

pub struct PurchasePlugin;

impl PurchasePlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PurchasePlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for PurchasePlugin {
    fn technical_name(&self) -> &'static str {
        "purchase"
    }

    /// Purchase models projected into the metadata registry from their
    /// `#[derive(Model)]` structs — supersedes migration `002_purchase_registry`.
    fn models(&self) -> Vec<&'static vortex_orm::model::ModelMeta> {
        use vortex_orm::model::Model;
        vec![crate::model::PurchaseOrder::meta()]
    }

    fn display_name(&self) -> &'static str {
        "Purchasing"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn summary(&self) -> &'static str {
        "Vendors, purchase orders, and stock-posting receipts"
    }

    fn description(&self) -> &'static str {
        "Procurement on top of the inventory ledger. Manage vendors (core contacts), \
         raise and confirm purchase orders, then record receipts that post stock moves \
         into inventory via the inventory service API. First module to compose the \
         inventory primitive rather than reinvent it."
    }

    fn author(&self) -> &'static str {
        "Vortex Core"
    }

    fn category(&self) -> &'static str {
        "Purchasing"
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["inventory"]
    }

    fn routes(&self) -> Router<Arc<AppState>> {
        handlers::purchase_routes()
    }

    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![
            MenuEntry::new("purchase.rfqs", "RFQs", "/purchase/rfqs", MenuGroup::Operations)
                .with_icon("shopping-cart")
                .with_priority(29),
            MenuEntry::new("purchase.orders", "Purchase Orders", "/purchase", MenuGroup::Operations)
                .with_icon("shopping-cart")
                .with_priority(30),
        ]
    }

    /// Plugin-owned migrations. `001_purchase` depends on the inventory
    /// tables (stock_product, stock_location) — guaranteed by registering
    /// this plugin after `vortex-inventory`. Its declared core dependency
    /// is commerce (currencies, migration 119).
    fn migrations(&self) -> Vec<PluginMigration> {
        vec![
            PluginMigration {
                name: "001_purchase",
                up_sql: MIG_001_PURCHASE,
                down_sql: Some(include_str!("../migrations/001_purchase/postgres_down.sql")),
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "002_purchase_registry",
                up_sql: MIG_002_REGISTRY,
                down_sql: None,
                requires_core_migration: Some("122_model_registry"),
            },
            PluginMigration {
                name: "003_vendor_bill",
                up_sql: MIG_003_VENDOR_BILL,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "004_rfq",
                up_sql: MIG_004_RFQ,
                down_sql: None,
                requires_core_migration: Some("122_model_registry"),
            },
        ]
    }

    fn translations(&self) -> Vec<Translation> {
        vec![
            // English
            Translation::new("en", "purchase", "menu.title", "Purchasing"),
            Translation::new("en", "purchase", "menu.orders", "Purchase Orders"),
            Translation::new("en", "purchase", "btn.new_order", "New Purchase Order"),
            Translation::new("en", "purchase", "field.vendor", "Vendor"),
            Translation::new("en", "purchase", "field.total", "Total"),
            Translation::new("en", "purchase", "state.draft", "Draft"),
            Translation::new("en", "purchase", "state.confirmed", "Confirmed"),
            Translation::new("en", "purchase", "state.received", "Received"),
            Translation::new("en", "purchase", "state.cancelled", "Cancelled"),
            Translation::new("en", "purchase", "msg.created", "Purchase order created"),
            // Malay
            Translation::new("ms", "purchase", "menu.title", "Belian"),
            Translation::new("ms", "purchase", "menu.orders", "Pesanan Belian"),
            Translation::new("ms", "purchase", "btn.new_order", "Pesanan Belian Baru"),
            Translation::new("ms", "purchase", "field.vendor", "Pembekal"),
            Translation::new("ms", "purchase", "field.total", "Jumlah"),
            Translation::new("ms", "purchase", "state.draft", "Draf"),
            Translation::new("ms", "purchase", "state.confirmed", "Disahkan"),
            Translation::new("ms", "purchase", "state.received", "Diterima"),
            Translation::new("ms", "purchase", "state.cancelled", "Dibatalkan"),
            Translation::new("ms", "purchase", "msg.created", "Pesanan belian dicipta"),
        ]
    }
}
