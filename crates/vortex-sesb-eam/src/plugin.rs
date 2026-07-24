//! [`SesbEamPlugin`] — the Plugin impl for the SESB electrical EAM vertical.

use std::sync::Arc;
use std::time::Duration;

use vortex_plugin_sdk::prelude::*;

use crate::handlers;

const MIG_001_FOUNDATION: &str = include_str!("../migrations/001_eam_foundation/postgres.sql");
const MIG_002_SEED: &str = include_str!("../migrations/002_eam_seed/postgres.sql");
const MIG_003_EQUIPMENT: &str = include_str!("../migrations/003_eam_equipment/postgres.sql");
const MIG_004_NETWORKS: &str = include_str!("../migrations/004_eam_networks/postgres.sql");
const MIG_005_OPERATIONS: &str = include_str!("../migrations/005_eam_operations/postgres.sql");
const MIG_006_GOVERNANCE: &str = include_str!("../migrations/006_eam_governance/postgres.sql");
const MIG_007_FIELD_PORTAL: &str = include_str!("../migrations/007_eam_field_portal/postgres.sql");
const MIG_008_POLICY: &str = include_str!("../migrations/008_eam_policy/postgres.sql");
const MIG_009_DIVISION: &str = include_str!("../migrations/009_eam_division_boundary/postgres.sql");

pub struct SesbEamPlugin;

impl SesbEamPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SesbEamPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for SesbEamPlugin {
    fn technical_name(&self) -> &'static str {
        "sesb_eam"
    }

    fn display_name(&self) -> &'static str {
        "SESB EAM"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn summary(&self) -> &'static str {
        "Electrical-utility Enterprise Asset Management (Sabah Electricity)"
    }

    fn description(&self) -> &'static str {
        "Enterprise Asset Management for an electrical utility: the full transmission, \
         distribution and underground-cable asset hierarchy (region → substation → bay → \
         equipment → component → part), condition monitoring, maintenance & defects, \
         reliability analytics (SAIDI/SAIFI), a field-technician portal and IEEE-1366 \
         reporting. A vertical specialization of the generic CMMS base."
    }

    fn author(&self) -> &'static str {
        "Vortex Core"
    }

    fn category(&self) -> &'static str {
        "Asset Management"
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["inventory"]
    }

    fn routes(&self) -> Router<Arc<AppState>> {
        handlers::routes()
    }

    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![
            // Dashboards & analytics (Phase 6) — top of the module menu
            MenuEntry::new("sesb_eam.dashboard", "EAM Dashboard", "/sesb-eam/dashboard", MenuGroup::Operations)
                .with_icon("layout-dashboard").with_priority(20),
            MenuEntry::new("sesb_eam.control_room", "Control Room", "/sesb-eam/control-room", MenuGroup::Operations)
                .with_icon("radio").with_priority(21).under("sesb_eam.dashboard"),
            MenuEntry::new("sesb_eam.apm", "Asset Health & Risk", "/sesb-eam/apm", MenuGroup::Operations)
                .with_icon("heart-pulse").with_priority(22).under("sesb_eam.dashboard"),
            MenuEntry::new("sesb_eam.executive", "Executive Summary", "/sesb-eam/executive", MenuGroup::Operations)
                .with_icon("briefcase").with_priority(23).under("sesb_eam.dashboard"),
            MenuEntry::new("sesb_eam.predictive", "Predictive Maintenance", "/sesb-eam/predictive", MenuGroup::Operations)
                .with_icon("trending-up").with_priority(24).under("sesb_eam.dashboard"),
            MenuEntry::new("sesb_eam.hierarchy", "Asset Hierarchy", "/sesb-eam/hierarchy", MenuGroup::Operations)
                .with_icon("git-fork").with_priority(26).under("sesb_eam.dashboard"),
            MenuEntry::new("sesb_eam.sld", "Single Line Diagram", "/sesb-eam/sld", MenuGroup::Operations)
                .with_icon("network").with_priority(27).under("sesb_eam.dashboard"),
            MenuEntry::new("sesb_eam.transmission_sld", "Transmission SLD", "/sesb-eam/transmission-sld", MenuGroup::Operations)
                .with_icon("cable").with_priority(28).under("sesb_eam.dashboard"),
            MenuEntry::new("sesb_eam.tower_map", "Tower Map", "/sesb-eam/tower-map", MenuGroup::Operations)
                .with_icon("map-pin").with_priority(29).under("sesb_eam.dashboard"),
            MenuEntry::new("sesb_eam.technician_map", "Technician Map", "/sesb-eam/technician-map", MenuGroup::Operations)
                .with_icon("map-pinned").with_priority(30).under("sesb_eam.dashboard"),
            MenuEntry::new("sesb_eam.site_map", "Site Map", "/sesb-eam/site-map", MenuGroup::Operations)
                .with_icon("map").with_priority(31).under("sesb_eam.dashboard"),
            MenuEntry::new("sesb_eam.reports", "Reports", "/sesb-eam/reports", MenuGroup::Operations)
                .with_icon("file-text").with_priority(25),
            MenuEntry::new("sesb_eam.substations", "Substations", "/sesb-eam/substations", MenuGroup::Operations)
                .with_icon("building")
                .with_priority(30),
            MenuEntry::new("sesb_eam.equipment", "Equipment", "/sesb-eam/equipment", MenuGroup::Operations)
                .with_icon("cpu")
                .with_priority(29),
            MenuEntry::new("sesb_eam.sites", "Sites", "/sesb-eam/sites", MenuGroup::Operations)
                .with_icon("map-pin")
                .with_priority(31),
            MenuEntry::new("sesb_eam.transmission_lines", "Transmission Lines", "/sesb-eam/transmission-lines", MenuGroup::Operations)
                .with_icon("git-branch")
                .with_priority(32),
            MenuEntry::new("sesb_eam.distribution_lines", "Distribution Lines", "/sesb-eam/distribution-lines", MenuGroup::Operations)
                .with_icon("share-2")
                .with_priority(33),
            MenuEntry::new("sesb_eam.ugc_lines", "UGC Lines", "/sesb-eam/ugc-lines", MenuGroup::Operations)
                .with_icon("minus")
                .with_priority(34),
            // Operations — work orders & field records (§3.6–3.7)
            MenuEntry::new("sesb_eam.maintenance", "Work Orders", "/sesb-eam/maintenance", MenuGroup::Operations)
                .with_icon("clipboard").with_priority(35),
            MenuEntry::new("sesb_eam.defects", "Defects", "/sesb-eam/defects", MenuGroup::Operations)
                .with_icon("alert-triangle").with_priority(36),
            MenuEntry::new("sesb_eam.inspections", "Inspections", "/sesb-eam/inspections", MenuGroup::Operations)
                .with_icon("search").with_priority(37),
            MenuEntry::new("sesb_eam.condition_monitoring", "Condition Monitoring", "/sesb-eam/condition-monitoring", MenuGroup::Operations)
                .with_icon("activity").with_priority(38),
            MenuEntry::new("sesb_eam.patrols", "Line Patrols", "/sesb-eam/patrols", MenuGroup::Operations)
                .with_icon("compass").with_priority(39),
            MenuEntry::new("sesb_eam.outages", "Outages", "/sesb-eam/outages", MenuGroup::Operations)
                .with_icon("zap-off").with_priority(40),
            MenuEntry::new("sesb_eam.vegetation", "Vegetation", "/sesb-eam/vegetation", MenuGroup::Operations)
                .with_icon("git-merge").with_priority(41),
            // Planning & governance (Phase 5)
            MenuEntry::new("sesb_eam.plans", "Maintenance Plans", "/sesb-eam/plans", MenuGroup::Operations)
                .with_icon("calendar").with_priority(42),
            MenuEntry::new("sesb_eam.verification", "Asset Verification", "/sesb-eam/verification", MenuGroup::Operations)
                .with_icon("shield").with_priority(43),
            MenuEntry::new("sesb_eam.agents", "Field Agents", "/sesb-eam/agents", MenuGroup::Operations)
                .with_icon("users").with_priority(44),
            MenuEntry::new("sesb_eam.agent_groups", "Agent Groups", "/sesb-eam/agent-groups", MenuGroup::Operations)
                .with_icon("users").with_priority(45).under("sesb_eam.agents"),
            MenuEntry::new("sesb_eam.leaves", "Agent Leave", "/sesb-eam/leaves", MenuGroup::Operations)
                .with_icon("calendar").with_priority(46).under("sesb_eam.agents"),
            // Configuration group (Odoo-style per-module submenu)
            MenuEntry::new("sesb_eam.config", "EAM Configuration", "#", MenuGroup::Operations)
                .with_icon("cog")
                .with_priority(95),
            MenuEntry::new("sesb_eam.regions", "Regions", "/sesb-eam/regions", MenuGroup::Operations)
                .with_icon("globe").with_priority(96).under("sesb_eam.config"),
            MenuEntry::new("sesb_eam.zones", "Zones", "/sesb-eam/zones", MenuGroup::Operations)
                .with_icon("layers").with_priority(97).under("sesb_eam.config"),
            MenuEntry::new("sesb_eam.kawasans", "Kawasans", "/sesb-eam/kawasans", MenuGroup::Operations)
                .with_icon("grid").with_priority(98).under("sesb_eam.config"),
            MenuEntry::new("sesb_eam.voltage_levels", "Voltage Levels", "/sesb-eam/voltage-levels", MenuGroup::Operations)
                .with_icon("zap").with_priority(99).under("sesb_eam.config"),
            MenuEntry::new("sesb_eam.manufacturers", "Manufacturers", "/sesb-eam/manufacturers", MenuGroup::Operations)
                .with_icon("briefcase").with_priority(100).under("sesb_eam.config"),
            MenuEntry::new("sesb_eam.asset_classes", "Asset Classes", "/sesb-eam/asset-classes", MenuGroup::Operations)
                .with_icon("tag").with_priority(101).under("sesb_eam.config"),
            MenuEntry::new("sesb_eam.asset_types", "Asset Types", "/sesb-eam/asset-types", MenuGroup::Operations)
                .with_icon("hash").with_priority(102).under("sesb_eam.config"),
            MenuEntry::new("sesb_eam.checklist_templates", "Checklist Templates", "/sesb-eam/checklist-templates", MenuGroup::Operations)
                .with_icon("check-square").with_priority(103).under("sesb_eam.config"),
            MenuEntry::new("sesb_eam.troubleshooting", "Troubleshooting Rules", "/sesb-eam/troubleshooting", MenuGroup::Operations)
                .with_icon("help-circle").with_priority(104).under("sesb_eam.config"),
        ]
    }

    /// Plugin-owned migrations. The foundation FKs into core `companies`,
    /// `users` and `countries`, so it requires the countries migration;
    /// the plugin is registered AFTER vortex-inventory for later phases
    /// that consume the stock ledger.
    fn migrations(&self) -> Vec<PluginMigration> {
        vec![
            PluginMigration {
                name: "001_eam_foundation",
                up_sql: MIG_001_FOUNDATION,
                down_sql: Some(include_str!("../migrations/001_eam_foundation/postgres_down.sql")),
                requires_core_migration: Some("011_countries"),
            },
            PluginMigration {
                name: "002_eam_seed",
                up_sql: MIG_002_SEED,
                down_sql: None,
                requires_core_migration: Some("011_countries"),
            },
            PluginMigration {
                name: "003_eam_equipment",
                up_sql: MIG_003_EQUIPMENT,
                down_sql: Some(include_str!("../migrations/003_eam_equipment/postgres_down.sql")),
                requires_core_migration: Some("011_countries"),
            },
            PluginMigration {
                name: "004_eam_networks",
                up_sql: MIG_004_NETWORKS,
                down_sql: Some(include_str!("../migrations/004_eam_networks/postgres_down.sql")),
                requires_core_migration: Some("011_countries"),
            },
            PluginMigration {
                name: "005_eam_operations",
                up_sql: MIG_005_OPERATIONS,
                down_sql: Some(include_str!("../migrations/005_eam_operations/postgres_down.sql")),
                requires_core_migration: Some("011_countries"),
            },
            PluginMigration {
                name: "006_eam_governance",
                up_sql: MIG_006_GOVERNANCE,
                down_sql: Some(include_str!("../migrations/006_eam_governance/postgres_down.sql")),
                requires_core_migration: Some("011_countries"),
            },
            PluginMigration {
                name: "007_eam_field_portal",
                up_sql: MIG_007_FIELD_PORTAL,
                down_sql: Some(include_str!("../migrations/007_eam_field_portal/postgres_down.sql")),
                requires_core_migration: Some("011_countries"),
            },
            // Starter Cedar policy for work-order transitions. Requires the
            // core policy engine (migration 115: `policy_rules` + Cedar).
            PluginMigration {
                name: "008_eam_policy",
                up_sql: MIG_008_POLICY,
                down_sql: Some(include_str!("../migrations/008_eam_policy/postgres_down.sql")),
                requires_core_migration: Some("115_policy_engine"),
            },
            // The DAMS/TAMS division boundary (§6.3): division column + derivation
            // triggers + orthogonal DAMS/TAMS roles. FKs into core `roles`.
            PluginMigration {
                name: "009_eam_division_boundary",
                up_sql: MIG_009_DIVISION,
                down_sql: Some(include_str!("../migrations/009_eam_division_boundary/postgres_down.sql")),
                requires_core_migration: Some("011_countries"),
            },
        ]
    }

    /// Scheduled jobs (§10.1).
    fn scheduled_actions(&self) -> Vec<ScheduledAction> {
        vec![
            ScheduledAction::new(
                ScheduledActionDef {
                    code: "sesb_eam.escalate_overdue",
                    name: "SESB EAM: escalate overdue work orders",
                    schedule: Schedule::Every(Duration::from_secs(24 * 60 * 60)),
                    enabled_by_default: true,
                },
                |state| async move { handlers::jobs::escalate_overdue(&state).await },
            ),
            ScheduledAction::new(
                ScheduledActionDef {
                    code: "sesb_eam.expire_stale_locations",
                    name: "SESB EAM: expire stale field-agent locations",
                    schedule: Schedule::Every(Duration::from_secs(15 * 60)),
                    enabled_by_default: true,
                },
                |state| async move { handlers::jobs::expire_stale_locations(&state).await },
            ),
            ScheduledAction::new(
                ScheduledActionDef {
                    code: "sesb_eam.refresh_derived_locations",
                    name: "SESB EAM: refresh job-derived agent locations",
                    schedule: Schedule::Every(Duration::from_secs(10 * 60)),
                    enabled_by_default: true,
                },
                |state| async move { handlers::jobs::refresh_derived_locations(&state).await },
            ),
        ]
    }

    fn translations(&self) -> Vec<Translation> {
        vec![
            Translation::new("en", "sesb_eam", "menu.title", "SESB EAM"),
            Translation::new("en", "sesb_eam", "menu.substations", "Substations"),
            Translation::new("en", "sesb_eam", "menu.sites", "Sites"),
            Translation::new("ms", "sesb_eam", "menu.title", "Pengurusan Aset SESB"),
            Translation::new("ms", "sesb_eam", "menu.substations", "Pencawang"),
            Translation::new("ms", "sesb_eam", "menu.sites", "Lokasi"),
        ]
    }
}
