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
use vortex_framework::{AppState, MenuEntry, MenuGroup, Plugin};

use crate::handlers;
use crate::ui;

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
}
