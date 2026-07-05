//! # Vortex Plugin SDK
//!
//! Everything a third-party vertical plugin needs in **one
//! dependency**.
//!
//! ## Quick start
//!
//! ```toml
//! [dependencies]
//! vortex-plugin-sdk = { path = "../vortex-core/crates/vortex-plugin-sdk" }
//! # (or, once published: vortex-plugin-sdk = "0.1")
//! ```
//!
//! ```rust,ignore
//! use vortex_plugin_sdk::prelude::*;
//!
//! pub struct MyPlugin;
//!
//! #[async_trait]
//! impl Plugin for MyPlugin {
//!     fn technical_name(&self) -> &'static str { "my_plugin" }
//!     fn display_name(&self)   -> &'static str { "My Plugin" }
//!     fn version(&self)        -> &'static str { "0.1.0" }
//!
//!     fn routes(&self) -> Router<Arc<AppState>> {
//!         // … your Axum routes here …
//!         Router::new()
//!     }
//!
//!     fn menu_entries(&self) -> Vec<MenuEntry> {
//!         vec![MenuEntry::new("my.list", "My Stuff", "/my-stuff", MenuGroup::Operations)]
//!     }
//!
//!     fn migrations(&self) -> Vec<PluginMigration> {
//!         vec![PluginMigration {
//!             name: "001_initial",
//!             up_sql: include_str!("../migrations/001_initial/postgres.sql"),
//!             down_sql: None,
//!             requires_core_migration: Some("001_initial_schema"),
//!         }]
//!     }
//! }
//! ```
//!
//! ## What's inside
//!
//! This crate re-exports symbols from six internal Vortex crates so
//! plugin authors don't need to know (or depend on) the internal
//! decomposition:
//!
//! | Internal crate      | What it provides to plugins                |
//! |----------------------|--------------------------------------------|
//! | `vortex-common`      | `VortexResult`, `VortexError`, ID types    |
//! | `vortex-framework`   | `Plugin` trait, `AppState`, menus, scheduler, reports, i18n |
//! | `vortex-orm`         | `ConnectionPool`, sequences, commerce primitives |
//! | `vortex-security`    | `AuditEntry`, `AuditAction`, `SigningKey`  |
//! | `vortex-workflow`    | `StateMachine`, `WorkflowEngine`           |
//! | `vortex-policy`      | `PolicyService`, Cedar types               |
//!
//! Plus re-exports of the third-party crates (`axum`, `sqlx`,
//! `serde`, `chrono`, `uuid`, `tokio`, `tracing`, `rust_decimal`)
//! at the exact versions the platform was compiled against, so
//! plugins cannot accidentally pull in an incompatible version.
//!
//! ## Stability contract
//!
//! The SDK follows the platform's versioning. Within a minor
//! version (0.1.x):
//!
//! - The `Plugin` trait may gain new methods with default impls
//!   (non-breaking).
//! - `AppState` may gain new fields (non-breaking for plugins that
//!   don't construct it — only the host binary does).
//! - No existing re-exported type will be removed or have its
//!   signature changed.
//!
//! Across minor versions (0.1 → 0.2), breaking changes are
//! possible and will be documented in a changelog.

// ─── Prelude ─────────────────────────────────────────────────────
// The subset of symbols most plugins need on every file. Import
// with `use vortex_plugin_sdk::prelude::*`.

pub mod prelude {
    // ── Core result/error types ──
    pub use vortex_common::{CompanyId, ModuleId, UserId, VortexError, VortexResult};

    // ── Plugin lifecycle ──
    pub use vortex_framework::{
        AppState, AuthUser, Db, DatabaseContext, MenuEntry, MenuGroup, Plugin, PluginMigration,
        PluginRegistry,
    };

    // ── Scheduler ──
    pub use vortex_framework::{Schedule, ScheduledAction, ScheduledActionDef, Scheduler};

    // ── Flash messages (one-shot toast across a redirect) ──
    pub use vortex_framework::{flash_redirect, FlashKind};

    // ── Record panels (cross-plugin detail-page contributions) ──
    pub use vortex_framework::{
        handle_record_panel_saves, render_record_panels, PanelSaveCtx, RecordPanel,
        RecordPanelDef, HOST_FORM_ID,
    };

    // ── Reports ──
    pub use vortex_framework::{
        ReportDef, ReportFormat, ReportOutput, ReportParams, ReportRegistry,
    };

    // ── i18n ──
    pub use vortex_framework::{
        format_date, Locale, Translation, TranslationService, DEFAULT_LOCALE,
    };

    // ── Outbound email ── (send via `framework::mail::send_default`)
    pub use vortex_framework::{EmailMessage, MailError};

    // ── Background jobs ── (enqueue via `framework::jobs::enqueue`)
    pub use vortex_framework::{JobContext, JobRegistry, NewJob};

    // ── Webhooks ── (emit events via `framework::webhooks::emit`)
    pub use vortex_framework::WebhookEndpoint;

    // ── Form engine ── (declare once: render + validate + save)
    pub use vortex_framework::form::{
        execute_form_save, load_record, render_form, FieldKind, FormConfig, FormField, FormMode,
        SaveOutcome,
    };

    // ── Audit ledger ── (every state change: `state.audit.log(...)`)
    pub use vortex_security::audit::{AuditAction, AuditEntry, AuditSeverity};

    // ── Async trait ──
    pub use async_trait::async_trait;

    // ── Axum re-exports (route building) ──
    pub use axum::{
        extract::{Extension, Form, Path, Query, State},
        http::StatusCode,
        response::{Html, IntoResponse, Redirect, Response},
        routing::{get, post},
        Router,
    };
    pub use std::sync::Arc;
}

// ─── Full module re-exports ──────────────────────────────────────
// For types not in the prelude, plugins use the full path:
// `vortex_plugin_sdk::orm::ConnectionPool`, etc.

/// Core types: errors, IDs, result wrappers.
pub use vortex_common as common;

/// Plugin lifecycle, AppState, menus, scheduler, reports, i18n.
pub use vortex_framework as framework;

/// ORM, connection pool, sequences, commerce primitives.
pub use vortex_orm as orm;

/// Audit ledger, signing, auth service.
pub use vortex_security as security;

/// Generic workflow engine, state machines.
pub use vortex_workflow as workflow;

/// Cedar ABAC policy engine.
pub use vortex_policy as policy;

// ─── Third-party re-exports ──────────────────────────────────────
// Pinned to the exact versions the platform uses. Plugins that
// import these through the SDK cannot have version conflicts.

pub use axum;
pub use async_trait;
pub use chrono;
pub use rust_decimal;
pub use serde;
pub use serde_json;
pub use sqlx;
pub use tokio;
pub use tracing;
pub use uuid;
