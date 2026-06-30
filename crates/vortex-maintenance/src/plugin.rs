//! [`MaintenancePlugin`] — the Plugin impl for the generic CMMS layer.

use std::sync::Arc;
use std::time::Duration;

use vortex_plugin_sdk::prelude::*;

use crate::handlers;

const MIG_001_MAINTENANCE: &str = include_str!("../migrations/001_maintenance/postgres.sql");
const MIG_002_REGISTRY: &str = include_str!("../migrations/002_maintenance_registry/postgres.sql");

pub struct MaintenancePlugin;

impl MaintenancePlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MaintenancePlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for MaintenancePlugin {
    fn technical_name(&self) -> &'static str {
        "maintenance"
    }

    fn display_name(&self) -> &'static str {
        "Maintenance"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn summary(&self) -> &'static str {
        "Assets, work orders, and preventive maintenance plans"
    }

    fn description(&self) -> &'static str {
        "Generic CMMS layer. Manages an asset register, corrective/preventive/inspection \
         work orders (with spare parts consumed from inventory on completion), and \
         preventive plans that a daily scheduler turns into due work orders. The base \
         that asset-intensive verticals (e.g. an electrical-utility EAM) specialize."
    }

    fn author(&self) -> &'static str {
        "Vortex Core"
    }

    fn category(&self) -> &'static str {
        "Maintenance"
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["inventory"]
    }

    fn routes(&self) -> Router<Arc<AppState>> {
        handlers::maintenance_routes()
    }

    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![
            MenuEntry::new("maintenance.work_orders", "Work Orders", "/maintenance", MenuGroup::Operations)
                .with_icon("wrench")
                .with_priority(40),
            MenuEntry::new("maintenance.assets", "Assets", "/maintenance/assets", MenuGroup::Operations)
                .with_icon("cpu")
                .with_priority(41),
            MenuEntry::new("maintenance.plans", "Maintenance Plans", "/maintenance/plans", MenuGroup::Operations)
                .with_icon("calendar")
                .with_priority(42),
            MenuEntry::new("maintenance.config", "Configuration", "#", MenuGroup::Operations)
                .with_icon("cog")
                .with_priority(90),
            MenuEntry::new("maintenance.asset_categories", "Asset Categories", "/maintenance/asset-categories", MenuGroup::Operations)
                .with_icon("tag")
                .with_priority(91)
                .under("maintenance.config"),
        ]
    }

    /// Plugin-owned migrations. `001_maintenance` FKs into inventory
    /// tables (stock_product, stock_location) — guaranteed by registering
    /// this plugin after `vortex-inventory`. Declared core dependency is
    /// contacts (asset vendor).
    fn migrations(&self) -> Vec<PluginMigration> {
        vec![
            PluginMigration {
                name: "001_maintenance",
                up_sql: MIG_001_MAINTENANCE,
                down_sql: Some(include_str!("../migrations/001_maintenance/postgres_down.sql")),
                requires_core_migration: Some("010_contacts"),
            },
            PluginMigration {
                name: "002_maintenance_registry",
                up_sql: MIG_002_REGISTRY,
                down_sql: None,
                requires_core_migration: Some("122_model_registry"),
            },
        ]
    }

    fn translations(&self) -> Vec<Translation> {
        vec![
            // English
            Translation::new("en", "maintenance", "menu.title", "Maintenance"),
            Translation::new("en", "maintenance", "menu.work_orders", "Work Orders"),
            Translation::new("en", "maintenance", "menu.assets", "Assets"),
            Translation::new("en", "maintenance", "menu.plans", "Maintenance Plans"),
            Translation::new("en", "maintenance", "type.corrective", "Corrective"),
            Translation::new("en", "maintenance", "type.preventive", "Preventive"),
            Translation::new("en", "maintenance", "type.inspection", "Inspection"),
            Translation::new("en", "maintenance", "state.draft", "Draft"),
            Translation::new("en", "maintenance", "state.in_progress", "In Progress"),
            Translation::new("en", "maintenance", "state.done", "Done"),
            // Malay
            Translation::new("ms", "maintenance", "menu.title", "Penyelenggaraan"),
            Translation::new("ms", "maintenance", "menu.work_orders", "Pesanan Kerja"),
            Translation::new("ms", "maintenance", "menu.assets", "Aset"),
            Translation::new("ms", "maintenance", "menu.plans", "Pelan Penyelenggaraan"),
            Translation::new("ms", "maintenance", "type.corrective", "Pembetulan"),
            Translation::new("ms", "maintenance", "type.preventive", "Pencegahan"),
            Translation::new("ms", "maintenance", "type.inspection", "Pemeriksaan"),
            Translation::new("ms", "maintenance", "state.draft", "Draf"),
            Translation::new("ms", "maintenance", "state.in_progress", "Dalam Proses"),
            Translation::new("ms", "maintenance", "state.done", "Selesai"),
        ]
    }

    /// Daily: turn due preventive plans into draft work orders and advance
    /// each plan's next date. Enabled by default — preventive maintenance
    /// is the whole point of having plans.
    fn scheduled_actions(&self) -> Vec<ScheduledAction> {
        vec![ScheduledAction::new(
            ScheduledActionDef {
                code: "maintenance.generate_work_orders",
                name: "Maintenance: generate due work orders",
                schedule: Schedule::Every(Duration::from_secs(24 * 60 * 60)),
                enabled_by_default: true,
            },
            |state| async move {
                handlers::generate_due_work_orders(&state).await
            },
        )]
    }
}
