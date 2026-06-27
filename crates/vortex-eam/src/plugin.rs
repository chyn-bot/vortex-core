//! EAM plugin — implements [`vortex_framework::Plugin`] for the EAM module.
//!
//! This is the "plugin binding" layer: the framework knows how to
//! register, mount, and query a `Plugin` implementor; this file is what
//! EAM provides for that contract. The actual handler functions still
//! live in `vortex-cli/src/commands/server.rs` and in
//! [`crate::handlers::eam_api_routes`], for now — Phase 0.3b will migrate
//! them into this crate so the entire EAM module lives under
//! `crates/vortex-eam/`.
//!
//! Today the plugin contributes:
//!
//! - **Stateless nested services**: the existing `eam_api_routes()`
//!   REST API, nested at `/api/eam` via the host's `nest_service`
//!   path. (Handlers pull the DB pool from the request's
//!   `DatabaseContext` extension, so they do not need shared
//!   `AppState`.)
//! - **Menu entries**: the sidebar items every EAM screen shows
//!   under the "Asset Management" group. Rendered by the host
//!   sidebar builder, filtered by user role and install state.
//!
//! It does **not** contribute stateful `Router<Arc<AppState>>` routes
//! yet — the 48 HTML `eam_*` handlers still live in `vortex-cli` and are
//! feature-gated there. Moving them here is the core piece of Phase 0.3b.

use std::sync::Arc;

use axum::Router;
use vortex_framework::{AppState, MenuEntry, MenuGroup, Plugin, PluginMigration};

use crate::handlers;
use crate::ui;

// EAM schema migrations — embedded directly into the crate binary
// via `include_str!` so the plugin is self-contained. Phase 0.6
// established this contract (`vortex-change` was the first consumer);
// Phase 0.7 applies it to EAM, moving the 11 migrations that used to
// live in `vortex-core/migrations/100_eam_*` through `113_eam_*` into
// `crates/vortex-eam/migrations/` and renumbering them 001–011 under
// the plugin's own number space.
//
// Every consumer of `asset_management:00N_*` in `vortex_migrations`
// is generated from these constants — adding a new migration means
// adding a directory, a const, and an entry to
// `EamPlugin::migrations()`.

const MIG_001_BASE: &str                  = include_str!("../migrations/001_base/postgres.sql");
const MIG_002_HIERARCHY: &str             = include_str!("../migrations/002_hierarchy_expansion/postgres.sql");
const MIG_003_MASTER_DATA: &str           = include_str!("../migrations/003_master_data/postgres.sql");
const MIG_004_EQUIPMENT_TYPES: &str       = include_str!("../migrations/004_equipment_types/postgres.sql");
const MIG_005_CONDITION_MONITORING: &str  = include_str!("../migrations/005_condition_monitoring/postgres.sql");
const MIG_006_MAINTENANCE_WORKFLOWS: &str = include_str!("../migrations/006_maintenance_workflows/postgres.sql");
const MIG_007_CHECKLIST_PLANS: &str       = include_str!("../migrations/007_checklist_plans/postgres.sql");
const MIG_008_TRANSMISSION: &str          = include_str!("../migrations/008_transmission/postgres.sql");
const MIG_009_SECURITY: &str              = include_str!("../migrations/009_security/postgres.sql");
const MIG_010_FIELD_ALIGNMENT: &str       = include_str!("../migrations/010_field_alignment/postgres.sql");
const MIG_011_CONDITION_METADATA: &str    = include_str!("../migrations/011_condition_metadata/postgres.sql");

/// The EAM plugin. Registered in the host binary's `PluginRegistry`
/// when the `eam` cargo feature is enabled.
pub struct EamPlugin;

impl EamPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EamPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Plugin for EamPlugin {
    fn technical_name(&self) -> &'static str {
        "asset_management"
    }

    fn display_name(&self) -> &'static str {
        "Enterprise Asset Management"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    /// EAM contributes a stateful HTML UI router covering all the
    /// `/eam/*` routes. Handlers live in [`crate::ui`] and take the
    /// shared [`AppState`] via `State<Arc<AppState>>`.
    fn routes(&self) -> Router<Arc<AppState>> {
        ui::eam_ui_routes()
    }

    /// EAM nests its REST API under `/api/eam/*` as a stateless
    /// sub-service. Handlers are in [`crate::handlers::eam_api_routes`]
    /// and pull the per-request DB pool from the `DatabaseContext`
    /// request extension.
    fn nested_services(&self) -> Vec<(String, Router)> {
        vec![("/api/eam".to_string(), handlers::eam_api_routes())]
    }

    /// Sidebar entries. Grouped under [`MenuGroup::Operations`] with
    /// the overview as the lowest-priority entry so it sorts first.
    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![
            MenuEntry::new("eam.dashboard", "Overview", "/eam", MenuGroup::Operations)
                .with_icon("building")
                .with_priority(10),
            MenuEntry::new("eam.sites", "Sites", "/eam/sites", MenuGroup::Operations)
                .with_icon("map-pin")
                .with_priority(20),
            MenuEntry::new("eam.assets", "Assets", "/eam/assets", MenuGroup::Operations)
                .with_icon("bolt")
                .with_priority(30),
            MenuEntry::new(
                "eam.functional_locations",
                "Functional Locations",
                "/eam/functional-locations",
                MenuGroup::Operations,
            )
            .with_icon("globe")
            .with_priority(40),
            MenuEntry::new(
                "eam.equipment",
                "Equipment",
                "/eam/equipment",
                MenuGroup::Operations,
            )
            .with_icon("cube")
            .with_priority(50),
            MenuEntry::new(
                "eam.work_orders",
                "Work Orders",
                "/eam/work-orders",
                MenuGroup::Operations,
            )
            .with_icon("clipboard-list")
            .with_priority(60),
            MenuEntry::new(
                "eam.inspections",
                "Inspections",
                "/eam/inspections",
                MenuGroup::Operations,
            )
            .with_icon("clipboard-check")
            .with_priority(70),
            MenuEntry::new(
                "eam.checklists",
                "Checklists",
                "/eam/checklists",
                MenuGroup::Operations,
            )
            .with_icon("check-circle")
            .with_priority(80),
            MenuEntry::new(
                "eam.plans",
                "Maintenance Plans",
                "/eam/plans",
                MenuGroup::Operations,
            )
            .with_icon("calendar")
            .with_priority(90),
            MenuEntry::new(
                "eam.transmission",
                "Transmission",
                "/eam/transmission",
                MenuGroup::Operations,
            )
            .with_icon("bolt")
            .with_priority(100),
            MenuEntry::new(
                "eam.sld",
                "Single Line Diagram",
                "/eam/sld",
                MenuGroup::Operations,
            )
            .with_icon("diagram")
            .with_priority(110),
            MenuEntry::new(
                "eam.condition",
                "Condition Monitoring",
                "/eam/condition",
                MenuGroup::Operations,
            )
            .with_icon("chart")
            .with_priority(120),
            MenuEntry::new(
                "eam.manufacturers",
                "Manufacturers",
                "/eam/manufacturers",
                MenuGroup::Operations,
            )
            .with_icon("factory")
            .with_priority(130),
            MenuEntry::new(
                "eam.configuration",
                "Configuration",
                "/eam/configuration",
                MenuGroup::Administration,
            )
            .with_icon("cog")
            .with_priority(500)
            .require_role("system_administrator"),
        ]
    }

    /// EAM's schema, shipped as plugin migrations. The migration
    /// runner applies these under the composite key
    /// `asset_management:00N_*` in `vortex_migrations` so they never
    /// collide with core migrations or with migrations from other
    /// plugins.
    ///
    /// Ordering is intra-plugin: these 11 migrations run in declared
    /// sequence after every core migration has been applied and
    /// after every `requires_core_migration` precondition is
    /// satisfied. The runner's "object already exists → record as
    /// applied" fallback means dev databases that still have the old
    /// `100_eam_*` through `113_eam_*` core-migration records will
    /// transition transparently — the plugin SQL hits existing
    /// tables, fails with "already exists", and the runner simply
    /// records the new `asset_management:00N_*` key as applied
    /// without re-running.
    ///
    /// All eleven declare a dependency on core migration
    /// `001_initial_schema` (for `users` and `companies` FKs) except
    /// `009_security`, which also needs `002_access_control`'s
    /// `model_access` table to insert its role grants. Rather than
    /// listing the exact shallowest dependency for each migration,
    /// every EAM migration asserts the *latest* core migration it
    /// actually needs — defensive but readable.
    fn migrations(&self) -> Vec<PluginMigration> {
        vec![
            PluginMigration {
                name: "001_base",
                up_sql: MIG_001_BASE,
                down_sql: None,
                requires_core_migration: Some("001_initial_schema"),
            },
            PluginMigration {
                name: "002_hierarchy_expansion",
                up_sql: MIG_002_HIERARCHY,
                down_sql: None,
                requires_core_migration: Some("001_initial_schema"),
            },
            PluginMigration {
                name: "003_master_data",
                up_sql: MIG_003_MASTER_DATA,
                down_sql: None,
                requires_core_migration: Some("001_initial_schema"),
            },
            PluginMigration {
                name: "004_equipment_types",
                up_sql: MIG_004_EQUIPMENT_TYPES,
                down_sql: None,
                requires_core_migration: Some("001_initial_schema"),
            },
            PluginMigration {
                name: "005_condition_monitoring",
                up_sql: MIG_005_CONDITION_MONITORING,
                down_sql: None,
                requires_core_migration: Some("001_initial_schema"),
            },
            PluginMigration {
                name: "006_maintenance_workflows",
                up_sql: MIG_006_MAINTENANCE_WORKFLOWS,
                down_sql: None,
                requires_core_migration: Some("001_initial_schema"),
            },
            PluginMigration {
                name: "007_checklist_plans",
                up_sql: MIG_007_CHECKLIST_PLANS,
                down_sql: None,
                requires_core_migration: Some("001_initial_schema"),
            },
            PluginMigration {
                name: "008_transmission",
                up_sql: MIG_008_TRANSMISSION,
                down_sql: None,
                requires_core_migration: Some("001_initial_schema"),
            },
            PluginMigration {
                name: "009_security",
                up_sql: MIG_009_SECURITY,
                down_sql: None,
                // Inserts into core `model_access` — needs the
                // access_control schema from 002.
                requires_core_migration: Some("002_access_control"),
            },
            PluginMigration {
                name: "010_field_alignment",
                up_sql: MIG_010_FIELD_ALIGNMENT,
                down_sql: None,
                requires_core_migration: Some("001_initial_schema"),
            },
            PluginMigration {
                name: "011_condition_metadata",
                up_sql: MIG_011_CONDITION_METADATA,
                down_sql: None,
                requires_core_migration: Some("001_initial_schema"),
            },
        ]
    }
}
