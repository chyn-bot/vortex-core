//! [`InventoryPlugin`] — the Plugin impl for the generic stock module.

use std::sync::Arc;
use std::time::Duration;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal;

use crate::handlers;

const MIG_001_INVENTORY: &str = include_str!("../migrations/001_inventory/postgres.sql");
const MIG_002_REGISTRY: &str = include_str!("../migrations/002_inventory_registry/postgres.sql");
const MIG_003_LOT_SERIAL: &str = include_str!("../migrations/003_lot_serial/postgres.sql");
const MIG_004_LOT_REGISTRY: &str = include_str!("../migrations/004_lot_registry/postgres.sql");
const MIG_005_TRADE_DESC: &str =
    include_str!("../migrations/005_trade_descriptions/postgres.sql");
const MIG_006_PRODUCT_DEFAULTS: &str =
    include_str!("../migrations/006_product_defaults/postgres.sql");
const MIG_007_LIST_PRICE: &str =
    include_str!("../migrations/007_list_price/postgres.sql");
const MIG_008_SCALE_INDEXES: &str =
    include_str!("../migrations/008_scale_indexes/postgres.sql");

pub struct InventoryPlugin;

impl InventoryPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for InventoryPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for InventoryPlugin {
    fn technical_name(&self) -> &'static str {
        "inventory"
    }

    fn display_name(&self) -> &'static str {
        "Inventory"
    }

    /// Inventory models projected into the metadata registry from their
    /// `#[derive(Model)]` structs — the single source of truth that supersedes
    /// the hand-seeded rows in migrations `002_inventory_registry` and
    /// `004_lot_registry`.
    fn models(&self) -> Vec<&'static vortex_orm::model::ModelMeta> {
        use vortex_orm::model::Model;
        vec![
            crate::model::StockProduct::meta(),
            crate::model::StockLocation::meta(),
            crate::model::StockMove::meta(),
            crate::model::StockLot::meta(),
        ]
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn summary(&self) -> &'static str {
        "Products, locations, and a double-entry stock ledger"
    }

    fn description(&self) -> &'static str {
        "Generic, always-on stock primitive. Manages products and categories, \
         warehouse locations, and stock moves posted through a double-entry ledger \
         that maintains on-hand quantities (with optional lot/serial tracking). \
         Other modules compose it via the public service API (post_move / resolve_lot) \
         to flow goods through the same ledger — purchasing receipts, maintenance \
         spare-part consumption, and so on."
    }

    fn author(&self) -> &'static str {
        "Vortex Core"
    }

    fn category(&self) -> &'static str {
        "Inventory"
    }

    /// CRUD routes for products, locations, moves, and the on-hand view.
    fn routes(&self) -> Router<Arc<AppState>> {
        handlers::inventory_routes()
    }

    /// Sidebar entries under Operations.
    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![
            MenuEntry::new("inventory.products", "Products", "/inventory", MenuGroup::Operations)
                .with_icon("box")
                .with_priority(20),
            MenuEntry::new(
                "inventory.moves",
                "Stock Moves",
                "/inventory/moves",
                MenuGroup::Operations,
            )
            .with_icon("truck")
            .with_priority(21),
            MenuEntry::new(
                "inventory.onhand",
                "On Hand",
                "/inventory/onhand",
                MenuGroup::Operations,
            )
            .with_icon("layers")
            .with_priority(22),
            MenuEntry::new(
                "inventory.lots",
                "Lots / Serials",
                "/inventory/lots",
                MenuGroup::Operations,
            )
            .with_icon("hash")
            .with_priority(23),
            // Configuration — master-data setup, collapsed by default and
            // nested under one collapsible parent (Odoo-style).
            MenuEntry::new(
                "inventory.config",
                "Configuration",
                "#",
                MenuGroup::Operations,
            )
            .with_icon("cog")
            .with_priority(90),
            MenuEntry::new(
                "inventory.categories",
                "Product Categories",
                "/inventory/categories",
                MenuGroup::Operations,
            )
            .with_icon("tag")
            .with_priority(91)
            .under("inventory.config"),
            MenuEntry::new(
                "inventory.locations",
                "Locations",
                "/inventory/locations",
                MenuGroup::Operations,
            )
            .with_icon("map-pin")
            .with_priority(92)
            .under("inventory.config"),
            MenuEntry::new(
                "inventory.uoms",
                "Units of Measure",
                "/inventory/uoms",
                MenuGroup::Operations,
            )
            .with_icon("ruler")
            .with_priority(93)
            .under("inventory.config"),
        ]
    }

    /// Plugin-owned migrations: the inventory tables + the model-registry
    /// rows that expose them to the generic list/pivot/API layer.
    fn migrations(&self) -> Vec<PluginMigration> {
        vec![
            PluginMigration {
                name: "001_inventory",
                up_sql: MIG_001_INVENTORY,
                down_sql: Some(include_str!("../migrations/001_inventory/postgres_down.sql")),
                // Needs commerce (uoms) + base schema (companies/users).
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "002_inventory_registry",
                up_sql: MIG_002_REGISTRY,
                down_sql: None,
                requires_core_migration: Some("122_model_registry"),
            },
            PluginMigration {
                name: "003_lot_serial",
                up_sql: MIG_003_LOT_SERIAL,
                down_sql: Some(include_str!("../migrations/003_lot_serial/postgres_down.sql")),
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "004_lot_registry",
                up_sql: MIG_004_LOT_REGISTRY,
                down_sql: None,
                requires_core_migration: Some("122_model_registry"),
            },
            PluginMigration {
                name: "005_trade_descriptions",
                up_sql: MIG_005_TRADE_DESC,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "006_product_defaults",
                up_sql: MIG_006_PRODUCT_DEFAULTS,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "007_list_price",
                up_sql: MIG_007_LIST_PRICE,
                down_sql: None,
                requires_core_migration: Some("119_commerce_primitives"),
            },
            PluginMigration {
                name: "008_scale_indexes",
                up_sql: MIG_008_SCALE_INDEXES,
                down_sql: Some(
                    "DROP INDEX IF EXISTS idx_stock_move_reference_id; \
                     DROP INDEX IF EXISTS idx_stock_move_reference_trgm;",
                ),
                requires_core_migration: Some("119_commerce_primitives"),
            },
        ]
    }

    /// Menu + field labels in English and Malay.
    fn translations(&self) -> Vec<Translation> {
        vec![
            // English
            Translation::new("en", "inventory", "menu.title", "Inventory"),
            Translation::new("en", "inventory", "menu.products", "Products"),
            Translation::new("en", "inventory", "menu.moves", "Stock Moves"),
            Translation::new("en", "inventory", "menu.onhand", "On Hand"),
            Translation::new("en", "inventory", "menu.lots", "Lots / Serials"),
            Translation::new("en", "inventory", "menu.locations", "Locations"),
            Translation::new("en", "inventory", "field.lot", "Lot / Serial"),
            Translation::new("en", "inventory", "btn.new_product", "New Product"),
            Translation::new("en", "inventory", "btn.new_move", "New Move"),
            Translation::new("en", "inventory", "field.code", "Code"),
            Translation::new("en", "inventory", "field.name", "Name"),
            Translation::new("en", "inventory", "field.quantity", "Quantity"),
            Translation::new("en", "inventory", "type.stockable", "Stockable"),
            Translation::new("en", "inventory", "type.consumable", "Consumable"),
            Translation::new("en", "inventory", "type.service", "Service"),
            Translation::new("en", "inventory", "msg.created", "Product created successfully"),
            // Malay
            Translation::new("ms", "inventory", "menu.title", "Inventori"),
            Translation::new("ms", "inventory", "menu.products", "Produk"),
            Translation::new("ms", "inventory", "menu.moves", "Pergerakan Stok"),
            Translation::new("ms", "inventory", "menu.onhand", "Baki Stok"),
            Translation::new("ms", "inventory", "menu.lots", "Lot / Bersiri"),
            Translation::new("ms", "inventory", "menu.locations", "Lokasi"),
            Translation::new("ms", "inventory", "field.lot", "Lot / Bersiri"),
            Translation::new("ms", "inventory", "btn.new_product", "Produk Baru"),
            Translation::new("ms", "inventory", "btn.new_move", "Pergerakan Baru"),
            Translation::new("ms", "inventory", "field.code", "Kod"),
            Translation::new("ms", "inventory", "field.name", "Nama"),
            Translation::new("ms", "inventory", "field.quantity", "Kuantiti"),
            Translation::new("ms", "inventory", "type.stockable", "Boleh Stok"),
            Translation::new("ms", "inventory", "type.consumable", "Boleh Guna"),
            Translation::new("ms", "inventory", "type.service", "Perkhidmatan"),
            Translation::new("ms", "inventory", "msg.created", "Produk berjaya dicipta"),
        ]
    }

    /// Background job: warn when stockable products fall to/below their
    /// reorder point. Opt-in — admins enable it once reorder levels are
    /// configured. Demonstrates the scheduler primitive on a real concern.
    fn scheduled_actions(&self) -> Vec<ScheduledAction> {
        vec![ScheduledAction::new(
            ScheduledActionDef {
                code: "inventory.reorder_alert",
                name: "Inventory: reorder-point alert",
                schedule: Schedule::Every(Duration::from_secs(24 * 60 * 60)), // daily
                enabled_by_default: false,
            },
            |state| async move {
                // Products whose total internal on-hand is at or below
                // their reorder_min (and a reorder_min is actually set).
                let low: Vec<(String, String)> = vortex_plugin_sdk::sqlx::query_as(
                    "SELECT p.code, p.name \
                     FROM stock_product p \
                     LEFT JOIN ( \
                         SELECT q.product_id, COALESCE(SUM(q.quantity), 0) AS on_hand \
                         FROM stock_quant q \
                         JOIN stock_location l ON l.id = q.location_id \
                         WHERE l.location_type = 'internal' \
                         GROUP BY q.product_id \
                     ) oh ON oh.product_id = p.id \
                     WHERE p.active AND p.product_type = 'stockable' \
                       AND p.reorder_min > 0 \
                       AND COALESCE(oh.on_hand, 0) <= p.reorder_min",
                )
                .fetch_all(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

                if !low.is_empty() {
                    vortex_plugin_sdk::tracing::warn!(
                        count = low.len() as i64,
                        products = ?low.iter().map(|(c, _)| c).collect::<Vec<_>>(),
                        "inventory products at or below reorder point"
                    );
                }
                Ok(())
            },
        )]
    }

    /// Report: On-Hand Valuation across internal locations.
    fn reports(&self) -> Vec<ReportDef> {
        vec![ReportDef::new(
            "inventory.onhand",
            "On-Hand Valuation",
            "Current on-hand quantity and value per product across internal locations",
            vec![ReportFormat::Html, ReportFormat::Csv, ReportFormat::Json],
            |state, params| async move {
                // (code, name, on_hand, cost, value)
                let rows: Vec<(String, String, rust_decimal::Decimal, rust_decimal::Decimal, rust_decimal::Decimal)> =
                    vortex_plugin_sdk::sqlx::query_as(
                        "SELECT p.code, p.name, \
                                COALESCE(SUM(q.quantity), 0) AS on_hand, \
                                p.cost, \
                                COALESCE(SUM(q.quantity), 0) * p.cost AS value \
                         FROM stock_product p \
                         LEFT JOIN stock_quant q ON q.product_id = p.id \
                         LEFT JOIN stock_location l \
                                ON l.id = q.location_id AND l.location_type = 'internal' \
                         WHERE p.active \
                         GROUP BY p.id, p.code, p.name, p.cost \
                         ORDER BY p.code",
                    )
                    .fetch_all(&state.db)
                    .await
                    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

                match params.format {
                    ReportFormat::Html => {
                        let esc = vortex_plugin_sdk::framework::html_escape;
                        let mut html = String::from(
                            "<!DOCTYPE html><html><head>\
                             <title>On-Hand Valuation</title>\
                             <style>\
                             body{font-family:sans-serif;margin:2em}\
                             table{border-collapse:collapse;width:100%}\
                             th,td{border:1px solid #ddd;padding:8px;text-align:left}\
                             th{background:#f5f5f5}td.num{text-align:right;font-variant-numeric:tabular-nums}\
                             @media print{body{margin:0}}\
                             </style></head><body>\
                             <h1>On-Hand Valuation</h1>\
                             <table><tr><th>Code</th><th>Product</th>\
                             <th>On Hand</th><th>Unit Cost</th><th>Value</th></tr>",
                        );
                        let mut total = rust_decimal::Decimal::ZERO;
                        for (code, name, on_hand, cost, value) in &rows {
                            total += *value;
                            html.push_str(&format!(
                                "<tr><td>{}</td><td>{}</td>\
                                 <td class=\"num\">{}</td><td class=\"num\">{}</td>\
                                 <td class=\"num\">{}</td></tr>",
                                esc(code),
                                esc(name),
                                on_hand,
                                cost,
                                value,
                            ));
                        }
                        html.push_str(&format!(
                            "<tr><th colspan=\"4\" style=\"text-align:right\">Total</th>\
                             <th class=\"num\">{total}</th></tr></table></body></html>"
                        ));
                        Ok(ReportOutput::html("onhand-valuation.html", html))
                    }
                    ReportFormat::Csv => {
                        let mut out = Vec::new();
                        out.extend_from_slice(b"Code,Product,OnHand,UnitCost,Value\n");
                        for (code, name, on_hand, cost, value) in &rows {
                            out.extend_from_slice(
                                format!(
                                    "\"{code}\",\"{name}\",{on_hand},{cost},{value}\n"
                                )
                                .as_bytes(),
                            );
                        }
                        Ok(ReportOutput::csv("onhand-valuation.csv", out))
                    }
                    ReportFormat::Json => {
                        let data: Vec<vortex_plugin_sdk::serde_json::Value> = rows
                            .iter()
                            .map(|(code, name, on_hand, cost, value)| {
                                vortex_plugin_sdk::serde_json::json!({
                                    "code": code,
                                    "name": name,
                                    "on_hand": on_hand.to_string(),
                                    "unit_cost": cost.to_string(),
                                    "value": value.to_string(),
                                })
                            })
                            .collect();
                        ReportOutput::json("onhand-valuation.json", &data)
                            .map_err(|e| VortexError::Internal(e.to_string()))
                    }
                }
            },
        )]
    }
}
