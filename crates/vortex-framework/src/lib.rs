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

pub mod auth;
pub mod menu;
pub mod plugin;
pub mod registry;
pub mod sidebar;
pub mod state;
pub mod ui;

pub use auth::{AuthUser, Db};
pub use menu::{MenuEntry, MenuGroup};
pub use plugin::Plugin;
pub use registry::PluginRegistry;
pub use sidebar::build_sidebar;
pub use state::{AppState, DatabaseContext};
pub use ui::{
    build_pagination_html, error_response, format_number, format_time_ago, forbidden_page,
    get_initials, html_escape,
};
