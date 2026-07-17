//! # Iwk — Vortex plugin
//!
//! Scaffolded by `vortex scaffold plugin`. Start here:
//!
//! - `model.rs`    — the `#[derive(Model)]` struct: the registry source
//!                   of truth. The default list & form are generated
//!                   from it, and `Plugin::models()` syncs it into
//!                   `ir_model` (no hand-seeded registry SQL).
//! - `plugin.rs`   — the [`Plugin`] impl: identity, routes, menu,
//!                   models, migrations. Add scheduled actions, reports
//!                   and translations as the module grows.
//! - `handlers.rs` — the HTTP surface: a list view (list framework),
//!                   create form, and a record page with status bar,
//!                   chatter and audit-backed status transitions.
//! - `migrations/` — plugin-owned schema, applied per tenant on
//!                   install. Never touch core `migrations/`.
//!
//! See `docs/CORE_FEATURES.md` for the full primitive toolbox.

pub mod billing;
pub mod gl;
pub mod handlers;
pub mod model;
pub mod plugin;

pub use plugin::IwkPlugin;
