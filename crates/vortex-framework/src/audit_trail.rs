//! Per-record audit trail rendering.
//!
//! A reusable timeline widget that any vertical can drop onto a record's
//! detail page. It reads the tenant's WORM `audit_log` for a single
//! `(resource_type, resource_id)` pair and renders each event with its
//! actor, relative time, and — when the writer recorded one — a
//! field-level before/after diff.
//!
//! The diff convention is a JSON object stored in `audit_log.details`:
//!
//! ```json
//! { "changes": [ { "field": "phone", "from": "012…", "to": "019…" } ] }
//! ```
//!
//! Writers that want field-level history should populate `changes` via
//! [`AuditEntry::with_details`]; entries without it still render as a
//! plain event line. This keeps the widget generic — core master data,
//! contacts, or any plugin record gets the same trail for free.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::ui::{format_time_ago, html_escape};

/// Map a raw audit action code to a human label and a DaisyUI dot colour.
fn action_style(action: &str) -> (&'static str, &'static str) {
    match action {
        "record_created" => ("Created", "bg-success"),
        "record_updated" => ("Updated", "bg-info"),
        "record_deleted" => ("Archived", "bg-warning"),
        _ => ("Changed", "bg-base-300"),
    }
}

/// Render the audit trail for one record as an HTML fragment (a DaisyUI
/// card). Safe to embed directly in a server-rendered page — every
/// dynamic value is HTML-escaped and there are no inline scripts.
///
/// Reads at most the 100 most recent entries. On any DB error it returns
/// an empty-state card rather than failing the host page.
pub async fn render_audit_trail(pool: &PgPool, resource_type: &str, resource_id: Uuid) -> String {
    let rows = sqlx::query(
        "SELECT timestamp, COALESCE(username, 'System') AS username, action, details \
         FROM audit_log \
         WHERE resource_type = $1 AND resource_id = $2 \
         ORDER BY timestamp DESC \
         LIMIT 100",
    )
    .bind(resource_type)
    .bind(resource_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut items = String::new();
    for r in &rows {
        let ts: DateTime<Utc> = r.get("timestamp");
        let username: String = r.get("username");
        let action: String = r.get("action");
        let details: Option<serde_json::Value> = r.try_get("details").ok();
        let (label, dot) = action_style(&action);

        // Render the field-level diff, if the writer recorded one.
        let mut changes_html = String::new();
        if let Some(changes) = details
            .as_ref()
            .and_then(|d| d.get("changes"))
            .and_then(|c| c.as_array())
        {
            for ch in changes {
                let field = ch.get("field").and_then(|v| v.as_str()).unwrap_or("");
                let from = value_to_display(ch.get("from"));
                let to = value_to_display(ch.get("to"));
                changes_html.push_str(&format!(
                    r#"<div class="text-xs mt-1 ml-1"><span class="font-mono text-base-content/70">{field}</span>: <span class="text-base-content/50 line-through">{from}</span> <span class="text-base-content/40">→</span> <span class="text-base-content/90">{to}</span></div>"#,
                    field = html_escape(field),
                    from = from,
                    to = to,
                ));
            }
        }

        items.push_str(&format!(
            r#"<li class="relative pl-6 pb-4 border-l border-base-300 last:border-transparent">
<span class="absolute -left-[5px] top-1 w-2.5 h-2.5 rounded-full {dot}"></span>
<div class="text-sm"><span class="font-medium">{label}</span>
<span class="text-base-content/50">· {user} · {ago}</span></div>
{changes}
</li>"#,
            dot = dot,
            label = label,
            user = html_escape(&username),
            ago = html_escape(&format_time_ago(ts)),
            changes = changes_html,
        ));
    }

    let body = if rows.is_empty() {
        r#"<p class="text-sm text-base-content/50">No history yet.</p>"#.to_string()
    } else {
        format!(r#"<ul class="mt-2">{}</ul>"#, items)
    };

    format!(
        r#"<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-2">History</h2>
{body}
</div></div>"#,
        body = body
    )
}

/// Format a JSON diff value for display. Null / missing renders as an
/// "(empty)" placeholder so a set-from-blank reads naturally.
fn value_to_display(v: Option<&serde_json::Value>) -> String {
    match v {
        None | Some(serde_json::Value::Null) => {
            r#"<span class="italic">(empty)</span>"#.to_string()
        }
        Some(serde_json::Value::String(s)) if s.is_empty() => {
            r#"<span class="italic">(empty)</span>"#.to_string()
        }
        Some(serde_json::Value::String(s)) => html_escape(s),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        Some(other) => html_escape(&other.to_string()),
    }
}
