//! Vortex Framework — the binding layer between modules and the runtime.
//!
//! This crate is the answer to the question *"what does it actually mean
//! for a Vortex module to be a plugin?"*. The foundational [`vortex-module`]
//! crate owns module metadata, dependency resolution, and the install /
//! upgrade / uninstall lifecycle. What it does **not** own is the binding
//! to the running HTTP server: how a module contributes routes, how its
//! sidebar entries end up in the rendered navigation, what shared state it
//! receives from the host.
//!
//! Those questions are what `vortex-framework` answers.
//!
//! # The three primitives
//!
//! - [`AppState`] — the struct every HTTP handler receives. Moved here
//!   from `vortex-cli` so plugin crates can depend on it without creating
//!   a circular dependency on the binary.
//! - [`Plugin`] — a trait a plugin crate implements to declare its HTTP
//!   routes and sidebar menu entries. One method per contribution point.
//! - [`PluginRegistry`] — what the host binary builds at startup. Plugins
//!   are registered in dependency order; the registry aggregates their
//!   routes (for `Router::merge`) and their menu entries (for the
//!   sidebar renderer).
//!
//! # Why this isn't baked into `vortex-module`
//!
//! `vortex-module` deliberately has no axum dependency. It is the module
//! system *abstraction* — manifests, dependency graphs, hooks, install
//! state persistence. `vortex-framework` is the *concrete binding* to a
//! specific runtime (the Axum HTTP server). A future `vortex-cli-api`
//! that hosts modules in a different runtime (GraphQL, gRPC, pure CLI)
//! would add its own binding crate alongside this one and keep
//! `vortex-module` intact.

pub mod api;
pub mod approval;
pub mod audit_trail;
pub mod auth;
pub mod i18n;
pub mod jobs;
pub mod list;
pub mod mail;
pub mod menu;
pub mod pdf;
pub mod plugin;
pub mod registry;
pub mod reports;
pub mod scheduler;
pub mod sidebar;
pub mod state;
pub mod status;
pub mod tracking;
pub mod ui;
pub mod user_reports;
pub mod webhooks;

pub use api::{ResolvedToken, TokenRow};
pub use webhooks::WebhookEndpoint;
pub use approval::{ApprovalRequest, ApprovalStep, DecisionOutcome, NewRequest};
pub use audit_trail::render_audit_trail;
pub use auth::{AuthUser, Db};
pub use jobs::{enqueue, JobContext, JobRegistry, JobWorker, NewJob};
pub use mail::{EmailMessage, MailError, MailSecurity, MailServer};
pub use status::{Stage, StageAction, StageActions, StageColor, StatusBar};
pub use tracking::{FieldKind, NewValueSource, Snapshot, TrackedField, Tracker};
pub use i18n::{
    format_date, locale_from_accept_language, sync_translations, Locale, Translation,
    TranslationService, DEFAULT_LOCALE,
};
// Note: i18n::format_number is NOT re-exported at the crate root
// because ui::format_number already exists. Use the full path
// `vortex_framework::i18n::format_number` when locale-aware number
// formatting is needed.
pub use list::{
    execute_list, render_list, CellRenderer, ListColumn, ListConfig, ListParams, ListResult,
    SortDir,
};
pub use menu::{MenuEntry, MenuGroup};
pub use plugin::{Plugin, PluginMigration};
pub use registry::PluginRegistry;
pub use reports::{
    render_report, reports_routes, ReportDef, ReportFormat, ReportOutput, ReportParams,
    ReportRegistry,
};
pub use scheduler::{Schedule, ScheduledAction, ScheduledActionDef, Scheduler};
pub use sidebar::build_sidebar;
pub use state::{AppState, DatabaseContext};
pub use ui::{
    build_pagination_html, error_response, format_number, format_time_ago, forbidden_page,
    get_initials, html_escape,
};
