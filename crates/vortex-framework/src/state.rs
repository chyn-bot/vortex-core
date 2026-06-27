//! Shared runtime state passed to every HTTP handler and plugin.
//!
//! `AppState` lived in `vortex-cli/src/commands/server.rs` until Phase 0.3,
//! at which point it moved here so plugin crates can declare
//! `Router<Arc<AppState>>` without an impossible circular dependency on
//! the binary crate.
//!
//! The composition is deliberate: everything in `AppState` is a **core**
//! service — DB pools, audit ledger, policy engine, module install cache.
//! Nothing here is domain-specific. If a field feels like it belongs to a
//! single module, it should live on that module's own state inside the
//! `Plugin` impl, not here.

use std::collections::HashSet;
use std::sync::Arc;

use sqlx::PgPool;
use tokio::sync::RwLock;
use vortex_orm::pool_manager::DatabasePoolManager;
use vortex_orm::ConnectionPool;
use vortex_policy::PolicyService;
use vortex_security::AuditLog;
use vortex_workflow::WorkflowEngine;

use crate::i18n::TranslationService;
use crate::registry::PluginRegistry;
use crate::reports::ReportRegistry;
use crate::scheduler::Scheduler;

/// Shared state handed to every HTTP handler via `axum::extract::State`.
///
/// This is the one type that crosses the boundary between `vortex-cli`
/// (the host binary) and plugin crates. Keep it stable: adding a field
/// is a workspace-wide recompile, and removing one breaks every plugin.
#[derive(Clone)]
pub struct AppState {
    /// Primary database connection pool. Used by handlers that do not
    /// go through the per-request `DatabaseContext` (for multi-tenant
    /// deployments this may not be the tenant's DB — see the middleware
    /// in `vortex-server`).
    pub db: PgPool,
    /// Wrapped pool used by crates that speak `vortex-orm`'s
    /// `ConnectionPool` API (the EAM crate and the policy engine, for
    /// example, accept this type rather than a raw `PgPool`).
    pub pool: Arc<ConnectionPool>,
    /// Per-database pool manager for multi-tenant deployments. In
    /// single-tenant mode this wraps the primary pool under the default
    /// database name.
    pub pool_manager: Arc<DatabasePoolManager>,
    /// Master database for the multi-tenant database registry, if
    /// multi-DB mode is enabled.
    pub master_db: Option<PgPool>,
    /// Argon2 hash of the master-mode administrative password, if set.
    pub master_password_hash: Option<String>,
    /// Optional regex filter restricting which managed databases the
    /// login page lists.
    pub db_filter: Option<String>,
    /// Whether multi-database mode is enabled.
    pub multi_db: bool,
    /// Primary database name (used as fallback in single-tenant mode).
    pub default_db: String,
    /// Cache of installed module technical names, refreshed by the
    /// module manager. Plugin `menu_entries` are filtered through this
    /// so unregistered plugins never appear in the sidebar.
    pub installed_modules: Arc<RwLock<HashSet<String>>>,
    /// WORM audit ledger (Phase 0.1). All state-changing handlers must
    /// emit audit events through this service — never via raw SQL
    /// inserts into `audit_log`, which would bypass the hash chain.
    pub audit: Arc<AuditLog>,
    /// Cedar-based policy engine (Phase 0.2). Handlers use
    /// `state.policy.check` to answer "can this specific user perform
    /// this specific action on this specific resource under these
    /// conditions?"
    pub policy: Arc<PolicyService>,
    /// Workflow engine (Phase 0.4). Plugins call
    /// `state.workflow.transition(...)` to advance state machines
    /// they have registered. Every transition is audit-logged to the
    /// WORM ledger and Cedar-gated, so this one field is how a
    /// plugin wires all three core primitives together.
    pub workflow: Arc<WorkflowEngine>,
    /// Plugin registry (Phase 0.3). Holds every `Plugin` the host has
    /// registered. The host walks this at route construction time
    /// (merging plugin routers) and at sidebar render time (collecting
    /// menu entries). Handlers reach it via `state.plugin_registry`
    /// when they need to know which plugins are currently active.
    pub plugin_registry: Arc<PluginRegistry>,
    /// Platform scheduler. Built at startup from every plugin's
    /// `scheduled_actions()` contribution and run as a single
    /// background supervisor task. Handlers can read this to enumerate
    /// currently-registered jobs; they cannot mutate it. See
    /// `crate::scheduler` for the full contract and the background
    /// supervisor loop.
    pub scheduler: Arc<Scheduler>,
    /// Translation service — in-memory cache of `(locale, key) →
    /// text` triples loaded from the `translations` table. Call
    /// `state.i18n.t(key, &locale)` from any handler to get the
    /// translated string with automatic fallback through the
    /// locale's chain.
    pub i18n: Arc<TranslationService>,
    /// Platform report registry. Built at startup from every
    /// plugin's `reports()` contribution. The generic HTTP route
    /// `/reports/:code` looks up reports here; direct consumers
    /// (scheduled email, export scripts) call
    /// `crate::reports::render_report(state, code, params)` to get
    /// the same bytes without going through HTTP.
    pub reports: Arc<ReportRegistry>,
}

/// Database context injected by the auth middleware for request-scoped
/// DB routing. In multi-tenant deployments the auth middleware looks up
/// the tenant for the current session and stuffs the corresponding pool
/// into the request extensions. Handlers extract it via the `Db`
/// extractor in `vortex-cli`.
#[derive(Clone)]
pub struct DatabaseContext {
    pub db_name: String,
    pub pool: Arc<ConnectionPool>,
    pub installed_modules: HashSet<String>,
}
