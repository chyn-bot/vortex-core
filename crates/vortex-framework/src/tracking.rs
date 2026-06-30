//! Declarative field-level change tracking — Vortex's analogue of Odoo's
//! `tracking=True` + chatter.
//!
//! A module declares, once, which of a model's fields are worth tracking
//! and how to render them. Before a write it takes a [`Snapshot`] of those
//! fields; after the write it asks the tracker to diff the snapshot against
//! the new values and post the changes to the WORM audit ledger. Pair with
//! [`crate::render_audit_trail`] to display that history on the record page.
//!
//! ```ignore
//! // Declare once (the `tracking=True` equivalent):
//! fn contact_tracker() -> Tracker {
//!     Tracker::new("contacts")
//!         .text("name", "Name")
//!         .text("email", "Email")
//!         .selection("contact_type", "Type")
//!         .boolean("is_company", "Company", "Company", "Individual")
//!         .money("credit_limit", "Credit Limit")
//!         .reference("country_id", "Country", "countries")
//! }
//!
//! // In the update handler:
//! let before = contact_tracker().snapshot(&db, id).await;
//! // ... perform the UPDATE ...
//! contact_tracker()
//!     .log_update(&state.audit, &db, &db_ctx.db_name,
//!                 user.id, &user.username, "contact", id, &name, &before, &form)
//!     .await;
//! ```
//!
//! Any new module gets record-level audit trails by declaring a `Tracker`
//! and making those two calls — no hand-written diff logic.

use std::collections::HashMap;

use sqlx::{PgPool, Row};
use uuid::Uuid;
use vortex_common::UserId;
use vortex_security::{AuditAction, AuditEntry, AuditLog, AuditSeverity};

use crate::ui::html_escape;

/// How a tracked field's value is read from the row / form and rendered
/// into the human-readable before/after strings shown on the trail.
pub enum FieldKind {
    /// Free text or a selection — compared as a trimmed string.
    Text,
    /// Boolean using web-form checkbox semantics: the key being *present*
    /// in the submitted form means `true`. Rendered via the labels.
    Bool { yes: &'static str, no: &'static str },
    /// Monetary / numeric value, normalised to 2 decimal places.
    Money,
    /// Foreign key resolved to a display name from `<table>.name`.
    Reference { table: &'static str },
}

/// One tracked field: its DB column / form key, a human label, and kind.
pub struct TrackedField {
    pub column: &'static str,
    pub label: &'static str,
    pub kind: FieldKind,
}

/// A model's tracking declaration — the set of fields whose changes get
/// recorded. Built fluently and reused on every write.
pub struct Tracker {
    table: &'static str,
    fields: Vec<TrackedField>,
}

/// Captured display values of the tracked fields at a point in time.
pub struct Snapshot {
    values: HashMap<&'static str, String>,
    found: bool,
}

/// Source of submitted new values. Implemented for the `HashMap<String,
/// String>` that axum's `Form` produces; custom form structs can impl it
/// too so they plug into the same tracker.
pub trait NewValueSource {
    /// Raw string for a field key, if submitted.
    fn raw(&self, key: &str) -> Option<&str>;
    /// Whether the key was present at all (checkbox-style booleans).
    fn present(&self, key: &str) -> bool;
}

impl NewValueSource for HashMap<String, String> {
    fn raw(&self, key: &str) -> Option<&str> {
        self.get(key).map(|s| s.as_str())
    }
    fn present(&self, key: &str) -> bool {
        self.contains_key(key)
    }
}

/// Reject anything that isn't a plain SQL identifier, so the static
/// table/column names can be safely interpolated. (They come from code,
/// not user input, but defence in depth is cheap.)
fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl Tracker {
    pub fn new(table: &'static str) -> Self {
        Self { table, fields: Vec::new() }
    }

    fn with(mut self, column: &'static str, label: &'static str, kind: FieldKind) -> Self {
        self.fields.push(TrackedField { column, label, kind });
        self
    }

    /// Track a text or selection field.
    pub fn text(self, column: &'static str, label: &'static str) -> Self {
        self.with(column, label, FieldKind::Text)
    }
    /// Alias for [`Tracker::text`] — reads better for dropdown fields.
    pub fn selection(self, column: &'static str, label: &'static str) -> Self {
        self.with(column, label, FieldKind::Text)
    }
    /// Track a checkbox boolean, rendered with the given labels.
    pub fn boolean(
        self,
        column: &'static str,
        label: &'static str,
        yes: &'static str,
        no: &'static str,
    ) -> Self {
        self.with(column, label, FieldKind::Bool { yes, no })
    }
    /// Track a monetary / numeric field (2dp).
    pub fn money(self, column: &'static str, label: &'static str) -> Self {
        self.with(column, label, FieldKind::Money)
    }
    /// Track a foreign key, resolving the id to `<ref_table>.name`.
    pub fn reference(
        self,
        column: &'static str,
        label: &'static str,
        ref_table: &'static str,
    ) -> Self {
        self.with(column, label, FieldKind::Reference { table: ref_table })
    }

    /// Capture the current display values of all tracked fields for `id`.
    /// Call this BEFORE performing the update.
    pub async fn snapshot(&self, db: &PgPool, id: Uuid) -> Snapshot {
        let mut values = HashMap::new();
        if !is_ident(self.table) || !self.fields.iter().all(|f| is_ident(f.column)) {
            return Snapshot { values, found: false };
        }
        let cols = self
            .fields
            .iter()
            .map(|f| f.column)
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("SELECT {cols} FROM {} WHERE id = $1", self.table);
        let row = sqlx::query(&sql).bind(id).fetch_optional(db).await.ok().flatten();

        let Some(r) = row else {
            return Snapshot { values, found: false };
        };
        for f in &self.fields {
            values.insert(f.column, read_old(&r, f, db).await);
        }
        Snapshot { values, found: true }
    }

    /// Diff a snapshot against the submitted values, returning the change
    /// set as `{field, from, to}` objects ready for the trail. Empty if
    /// the snapshot was never found (e.g. a brand-new record).
    pub async fn diff<N: NewValueSource>(
        &self,
        db: &PgPool,
        before: &Snapshot,
        new: &N,
    ) -> Vec<serde_json::Value> {
        let mut changes = Vec::new();
        if !before.found {
            return changes;
        }
        for f in &self.fields {
            let from = before.values.get(f.column).cloned().unwrap_or_default();
            let to = read_new(db, f, new).await;
            if from != to {
                changes.push(serde_json::json!({
                    "field": f.label,
                    "from": from,
                    "to": to,
                }));
            }
        }
        changes
    }

    /// Diff and post a `RecordUpdated` audit event scoped to `db_name`, so
    /// the entry lands in the tenant ledger and powers the history panel.
    /// The "auto-post" half of the Odoo-style pattern.
    #[allow(clippy::too_many_arguments)]
    pub async fn log_update<N: NewValueSource>(
        &self,
        audit: &AuditLog,
        db: &PgPool,
        db_name: &str,
        user_id: Uuid,
        username: &str,
        resource_type: &str,
        resource_id: Uuid,
        resource_name: &str,
        before: &Snapshot,
        new: &N,
    ) {
        let changes = self.diff(db, before, new).await;
        let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
            .with_user(UserId(user_id))
            .with_username(username)
            .with_database(db_name)
            .with_resource(resource_type, resource_id.to_string())
            .with_resource_name(resource_name)
            .with_details(serde_json::json!({ "changes": changes }));
        if let Err(e) = audit.log(entry).await {
            tracing::error!(error = %e, "tracked-update audit write failed");
        }
    }
}

/// Read & format a field's OLD value from a fetched row.
async fn read_old(row: &sqlx::postgres::PgRow, f: &TrackedField, db: &PgPool) -> String {
    match &f.kind {
        FieldKind::Text => row.try_get::<Option<String>, _>(f.column).ok().flatten().unwrap_or_default(),
        FieldKind::Bool { yes, no } => {
            let b = row.try_get::<bool, _>(f.column).unwrap_or(false);
            if b { yes.to_string() } else { no.to_string() }
        }
        FieldKind::Money => {
            // Format identically to the new-value side (`{:.2}` on f64) so an
            // untouched amount never registers as a spurious change.
            let d = row
                .try_get::<Option<rust_decimal::Decimal>, _>(f.column)
                .ok()
                .flatten()
                .unwrap_or_default();
            format!("{d:.2}")
        }
        FieldKind::Reference { table } => {
            let id: Option<Uuid> = row.try_get(f.column).ok();
            resolve_name(db, table, id).await
        }
    }
}

/// Read & format a field's NEW value from the submitted form.
async fn read_new<N: NewValueSource>(db: &PgPool, f: &TrackedField, new: &N) -> String {
    match &f.kind {
        FieldKind::Text => new.raw(f.column).map(|s| s.trim().to_string()).unwrap_or_default(),
        FieldKind::Bool { yes, no } => {
            if new.present(f.column) { yes.to_string() } else { no.to_string() }
        }
        FieldKind::Money => {
            let v = new.raw(f.column).and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0);
            format!("{v:.2}")
        }
        FieldKind::Reference { table } => {
            let id = new.raw(f.column).filter(|s| !s.is_empty()).and_then(|s| s.parse::<Uuid>().ok());
            resolve_name(db, table, id).await
        }
    }
}

/// Resolve a reference id to its `name`. Empty for None / unknown.
async fn resolve_name(db: &PgPool, table: &str, id: Option<Uuid>) -> String {
    let Some(id) = id else { return String::new() };
    if !is_ident(table) {
        return String::new();
    }
    let sql = format!("SELECT name FROM {table} WHERE id = $1");
    let name: Option<String> = sqlx::query_scalar(&sql)
        .bind(id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
    // Names are echoed into the trail; the renderer escapes, but keep the
    // stored value clean too.
    html_escape(name.as_deref().unwrap_or(""))
}
