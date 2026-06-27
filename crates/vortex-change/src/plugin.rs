//! [`ChangeRequestPlugin`] — the [`vortex_framework::Plugin`] impl.
//!
//! This is the tiny binding layer that tells the host binary what the
//! Change Request module contributes:
//!
//! - **Identity**: technical name `change_request`, used for the
//!   install state key and the route namespace.
//! - **State machines**: one machine, the CR workflow from
//!   [`crate::cr_state_machine`], which the host registers into the
//!   shared [`vortex_workflow::WorkflowEngine`] at startup.
//! - **Routes**: the HTML list/detail/form handlers from
//!   [`crate::handlers::cr_routes`]. Merged into the host's main
//!   router so `/change-requests/*` is a first-class URL.
//! - **Menu entries**: one sidebar item under Operations, visible to
//!   any authenticated user (per-action authorization is Cedar's job,
//!   not the sidebar filter's).
//!
//! `on_startup` is a no-op today — the state machine is compile-time
//! constant and there's no policy seeding beyond what the plugin's
//! own migration inserts. A later phase may load `change_request`
//! Cedar policies dynamically here so policy edits don't require a
//! migration.

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use vortex_common::VortexResult;
use vortex_framework::{AppState, MenuEntry, MenuGroup, Plugin, PluginMigration};
use vortex_workflow::StateMachine;

use crate::handlers::cr_routes;
use crate::state_machine::cr_state_machine;

/// The CR schema migration, embedded directly in the binary via
/// `include_str!`. The host's `vortex db migrate` command applies
/// this after all core migrations, scoped under this plugin's
/// technical name (`change_request:001_change_requests`) in the
/// `vortex_migrations` tracking table.
///
/// This is a demonstrator for the Plugin migration contract: the
/// entire plugin, including its schema, is self-contained in the
/// crate. No files in the host's `migrations/` directory.
const CR_MIGRATION_UP: &str = include_str!("../migrations/001_change_requests/postgres.sql");
const CR_MIGRATION_DOWN: &str =
    include_str!("../migrations/001_change_requests/postgres_down.sql");

/// The Change Request plugin. Registered in the host binary's
/// [`vortex_framework::PluginRegistry`] when the `cr` cargo feature
/// is enabled on `vortex-cli`.
pub struct ChangeRequestPlugin;

impl ChangeRequestPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ChangeRequestPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for ChangeRequestPlugin {
    fn technical_name(&self) -> &'static str {
        "change_request"
    }

    fn display_name(&self) -> &'static str {
        "Change Requests"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    /// Returns the CR router. All routes are under `/change-requests/*`
    /// and receive the shared [`AppState`] so they can call
    /// `state.workflow.transition(...)`, `state.audit.log(...)`, and
    /// `state.policy.check(...)` — the three core primitives.
    fn routes(&self) -> Router<Arc<AppState>> {
        cr_routes()
    }

    /// One state machine: the 7-state CR lifecycle. The host binary
    /// collects this during startup and registers it into the shared
    /// [`vortex_workflow::WorkflowEngine`] before constructing
    /// `AppState`, so handlers can call
    /// `state.workflow.transition(...)` without knowing that this
    /// plugin is the owner of the `change_request` workflow type.
    fn state_machines(&self) -> Vec<StateMachine> {
        vec![cr_state_machine()]
    }

    /// Sidebar entry. Lives under the Operations group so operators
    /// see "Change Requests" alongside other operational modules.
    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![MenuEntry::new(
            "change_request.list",
            "Change Requests",
            "/change-requests",
            MenuGroup::Operations,
        )
        .with_icon("clipboard-check")
        .with_priority(200)]
    }

    /// The CR plugin's schema. Embedded in the binary — no external
    /// migration directory needed. Depends on `116_workflow_engine`
    /// because every CR's `workflow_instance_id` is a FK into
    /// `workflow_instances` from that core migration.
    fn migrations(&self) -> Vec<PluginMigration> {
        vec![PluginMigration {
            name: "001_change_requests",
            up_sql: CR_MIGRATION_UP,
            down_sql: Some(CR_MIGRATION_DOWN),
            requires_core_migration: Some("116_workflow_engine"),
        }]
    }

    /// No-op today. Phase 0.6 may load dynamic Cedar policies from a
    /// plugin-owned `change_request_policies` table here.
    async fn on_startup(&self, _state: &AppState) -> VortexResult<()> {
        Ok(())
    }
}
