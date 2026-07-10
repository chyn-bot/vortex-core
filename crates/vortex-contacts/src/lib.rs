//! # Vortex Contacts Plugin
//!
//! The first vertical built entirely against `vortex-plugin-sdk`.
//! Exercises **every core primitive** on a simple domain (business
//! contacts) to prove the platform works end-to-end:
//!
//! | Primitive          | How it's used here                                  |
//! |--------------------|-----------------------------------------------------|
//! | `PluginMigration`  | `contact_tags` + `contact_tag_rel` extension tables |
//! | Sequence           | Auto-generated contact codes: `CNT/000001`          |
//! | Translation        | Menu label + button text in English + Malay          |
//! | Scheduled action   | Deactivate stale contacts (not updated in 365 days) |
//! | Report             | Contact directory as HTML, CSV, and JSON             |
//! | Audit logging      | Logged on contact creation via WORM ledger           |
//! | Routes + menus     | CRUD list/create endpoints + sidebar entry           |
//!
//! ## Why a separate crate?
//!
//! Contacts handlers used to live inline in `vortex-cli/src/commands/
//! server.rs` with a synthetic `ContactsBuiltinPlugin` that only
//! contributed a sidebar entry. This crate replaces that pattern with
//! a real plugin — proving the SDK contract is sufficient for a
//! full-featured module with zero host-binary code changes beyond
//! the registration line.

pub mod handlers;
pub mod model;
pub mod plugin;

pub use model::Contact;
pub use plugin::ContactsPlugin;
