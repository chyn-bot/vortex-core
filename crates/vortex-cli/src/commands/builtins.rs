//! Synthetic "built-in" plugins owned by the host binary itself.
//!
//! These are not real plugin crates. They are lightweight [`Plugin`]
//! implementations registered inline in `server.rs` that exist to
//! feed the plugin registry with menu entries for **features whose
//! handlers still live in the host binary**. They are a transitional
//! seam, not a long-term design.
//!
//! ## Why this exists
//!
//! Phase 0.3 extracted EAM into `crates/vortex-eam/` and Phase 0.5
//! created `crates/vortex-change/`. But a handful of historical
//! modules — Contacts in particular — still have their HTTP handlers
//! hardcoded in `crates/vortex-cli/src/commands/server.rs` because
//! moving them is a separate project.
//!
//! Before Phase 0.6 the sidebar had a hardcoded
//! `if installed.contains("contacts")` check inside the framework
//! crate, which meant the framework knew about a specific module by
//! name. That violates the "framework has no plugin knowledge"
//! invariant. The synthetic `ContactsBuiltinPlugin` here replaces
//! that hack: the host binary registers it like any other plugin,
//! the framework iterates plugins uniformly, and the sidebar
//! composition stays data-driven.
//!
//! When Contacts is eventually extracted into `crates/vortex-contacts/`
//! with its own handlers + migrations, delete this file and register
//! the real plugin instead. The change is local to `server.rs`.

use std::sync::Arc;

use axum::Router;
use vortex_framework::{AppState, MenuEntry, MenuGroup, Plugin};

/// Synthetic plugin for the built-in Contacts module. Contributes
/// the sidebar entry only — the actual HTTP handlers are still
/// registered directly in `server.rs::build_router` and will stay
/// there until Contacts is extracted into its own crate.
pub struct ContactsBuiltinPlugin;

impl Plugin for ContactsBuiltinPlugin {
    fn technical_name(&self) -> &'static str {
        "contacts"
    }

    fn display_name(&self) -> &'static str {
        "Contacts"
    }

    fn version(&self) -> &'static str {
        // Tracks the host binary version, not an independent
        // release — this is a synthetic plugin, not a real module.
        env!("CARGO_PKG_VERSION")
    }

    /// No routes — the real handlers are registered inline in
    /// `server.rs::build_router`. Returning an empty router here is
    /// correct; the merge is a no-op.
    fn routes(&self) -> Router<Arc<AppState>> {
        Router::new()
    }

    /// One sidebar entry under Operations. The framework filters
    /// entries by install state (`installed_modules`) before
    /// rendering, so Contacts still vanishes from the sidebar if an
    /// admin uninstalls it through the module manager.
    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![MenuEntry::new(
            "contacts.list",
            "Contacts",
            "/contacts",
            MenuGroup::Operations,
        )
        .with_icon("users")
        .with_priority(10)]
    }
}
