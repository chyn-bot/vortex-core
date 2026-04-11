//! The [`Plugin`] trait — what a plugin crate implements to plug in.
//!
//! A plugin contributes three things to the host binary:
//!
//! 1. **Identity**: a stable technical name, a human name, a version.
//!    The host uses the technical name to key the install state in
//!    `installed_modules` and to namespace the plugin's route mount
//!    point.
//! 2. **HTTP routes**: an `axum::Router<Arc<AppState>>` fragment that
//!    the host merges into its main router. The plugin decides its
//!    path layout; the host does not rewrite URLs.
//! 3. **Menu entries**: a list of [`crate::MenuEntry`] items that
//!    appear in the sidebar under their chosen [`crate::MenuGroup`].
//!
//! ## Route mounting convention
//!
//! Plugins return a Router that already knows its own path prefix — a
//! plugin that serves `/eam/*` routes should construct its router with
//! those absolute paths and the host will `merge` it into the main
//! router. This is deliberately simpler than nesting under a
//! plugin-controlled prefix: plugins that serve both `/api/eam/*` and
//! `/eam/*` (API + HTML) would otherwise need two mount points, one
//! per URL subtree.
//!
//! ## State
//!
//! Every plugin router uses the shared [`crate::AppState`] as its state
//! type. Plugins that need plugin-specific state should wrap it in an
//! `Arc` and store it on their plugin struct, then close over it in
//! their route handlers; they must not extend `AppState`.
//!
//! ## Why not async?
//!
//! `routes` and `menu_entries` are synchronous because they are called
//! once during host startup and should return immediately. `on_install`
//! and `on_uninstall` are async because they may hit the database.

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use vortex_common::VortexResult;
use vortex_workflow::StateMachine;

use crate::menu::MenuEntry;
use crate::state::AppState;

/// A database migration contributed by a plugin.
///
/// Plugins embed their migration SQL directly in the crate binary
/// via `include_str!` so the plugin is self-contained — installing a
/// plugin means adding a crate dep and nothing else; no files to
/// copy into the host's `migrations/` directory.
///
/// ## Naming and uniqueness
///
/// `name` is **plugin-local** — each plugin starts its own number
/// space at `001`. The migration runner records applied plugin
/// migrations under a composite key `<module>:<name>` (e.g.
/// `change_request:001_change_requests`) so two plugins can both
/// have a `001_initial` without colliding with each other or with
/// the core's `001_initial_schema`.
///
/// ## What core migrations this plugin depends on
///
/// Plugins that reference core tables (`users`, `companies`,
/// `workflow_instances`, `audit_log`, `policy_rules`) should set
/// `requires_core_migration` to the last core migration that shipped
/// the table they need. The runner fails fast with a clear error if
/// the core is older than that, instead of producing a confusing
/// `relation "foo" does not exist` deep in the SQL.
#[derive(Debug, Clone)]
pub struct PluginMigration {
    /// Plugin-local migration name. Must start with a zero-padded
    /// sequence number for deterministic ordering (e.g.
    /// `001_change_requests`).
    pub name: &'static str,
    /// Postgres SQL to run when applying this migration. Typically
    /// embedded via `include_str!("migrations/001_foo/postgres.sql")`.
    pub up_sql: &'static str,
    /// Optional rollback SQL. `None` means the migration is
    /// irreversible (matches the Phase 0.1 audit WORM pattern).
    pub down_sql: Option<&'static str>,
    /// The last core migration this plugin's schema depends on. If
    /// the migration runner finds the target database is missing
    /// this core migration, it aborts with a clear error instead of
    /// trying to run the plugin SQL against a half-built core.
    /// `None` means "this plugin has no core dependencies" — rare.
    pub requires_core_migration: Option<&'static str>,
}

/// A plugin contributes routes and menu entries to the host binary.
///
/// Implementors live in their own crate (e.g. `vortex-eam`,
/// `vortex-change`) and depend on `vortex-framework` but not on the
/// host binary. The host collects every registered `Arc<dyn Plugin>`
/// into a [`crate::PluginRegistry`] at startup and calls `routes` and
/// `menu_entries` exactly once each.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Stable technical name used for namespacing and install tracking.
    /// Must match the `technical_name` column in the `installed_modules`
    /// table if the plugin is persisted there. Lowercase, snake_case.
    fn technical_name(&self) -> &'static str;

    /// Human-readable display name for the plugin (admin panel, logs).
    fn display_name(&self) -> &'static str;

    /// Semver version string, e.g. "0.1.0".
    fn version(&self) -> &'static str;

    /// Return the plugin's stateful HTTP routes as an axum `Router`
    /// fragment. Handlers in this router receive `Arc<AppState>` via
    /// `State` extraction.
    ///
    /// The returned router is `merge`d into the host's main router, so
    /// the plugin is responsible for its own URL layout. Multiple
    /// plugins must not define overlapping routes; conflicts are a
    /// startup error detected by the registry.
    ///
    /// Default: empty. Plugins that only expose nested services (see
    /// [`Plugin::nested_services`]) or only contribute menu entries do
    /// not need to override this.
    fn routes(&self) -> Router<Arc<AppState>> {
        Router::new()
    }

    /// Return stateless sub-services the plugin wants nested at a
    /// specific path prefix. Each entry is `(prefix, router)` and is
    /// nested into the host with `Router::nest_service`.
    ///
    /// Use this for plugin subsystems that manage their own state
    /// (database pools injected via request extensions, etc.) rather
    /// than sharing `AppState`. The EAM plugin's `/api/eam/*` REST API
    /// is one such case — its handlers pull the DB pool from the
    /// request's `DatabaseContext` extension, not from shared state.
    ///
    /// Default: empty.
    fn nested_services(&self) -> Vec<(String, Router)> {
        Vec::new()
    }

    /// Return the plugin's sidebar menu entries. Host aggregates these
    /// across all plugins, sorts by group+priority, filters by the
    /// current user's role set, and renders into the sidebar shell.
    ///
    /// Default: no entries — the plugin is "headless" (exposes routes
    /// only, no UI navigation).
    fn menu_entries(&self) -> Vec<MenuEntry> {
        Vec::new()
    }

    /// Return the workflow state machines this plugin contributes.
    /// The host builds one shared [`vortex_workflow::WorkflowEngine`]
    /// during startup and registers every plugin's machines into it
    /// before creating `AppState`, so handlers can call
    /// `state.workflow.transition(...)` without knowing which plugin
    /// owns which machine.
    ///
    /// Plugins that use workflows should return their machines here;
    /// plugins that don't use workflows leave the default empty impl.
    fn state_machines(&self) -> Vec<StateMachine> {
        Vec::new()
    }

    /// Return the database migrations this plugin ships with. The
    /// migration runner (`vortex db migrate`) applies these **after**
    /// all core migrations, scoped under the plugin's technical name,
    /// so two plugins can safely have migrations with the same local
    /// name.
    ///
    /// Plugins embed their SQL with `include_str!` so the crate is
    /// self-contained and the host binary does not need to ship a
    /// filesystem `migrations/` directory for the plugin.
    ///
    /// Default: no migrations — the plugin is stateless or reuses
    /// existing core tables only.
    fn migrations(&self) -> Vec<PluginMigration> {
        Vec::new()
    }

    /// Called once during host startup after the plugin is registered
    /// but before its routes are mounted. Use this for any initial
    /// setup that cannot be done in a synchronous constructor: loading
    /// policies into the Cedar engine, priming caches, seeding
    /// optional defaults, etc.
    ///
    /// Default: no-op.
    async fn on_startup(&self, _state: &AppState) -> VortexResult<()> {
        Ok(())
    }
}
