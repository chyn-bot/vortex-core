//! Cross-plugin record panels.
//!
//! A plugin can contribute a panel to another module's record detail
//! page without that module depending on it — the Odoo-inheritance
//! equivalent for record forms, dependency-safe. The owning module
//! calls [`render_record_panels`] with its model name; every
//! registered plugin's panels for that model render in priority
//! order. A panel that errors is skipped with a warning — a broken
//! contributor must never take down the host page.
//!
//! ```rust,ignore
//! // In the CONTRIBUTING plugin (e.g. accounting adds tax identity
//! // to the contacts form):
//! fn record_panels(&self) -> Vec<RecordPanel> {
//!     vec![RecordPanel::new(
//!         RecordPanelDef { model: "contacts", title: "Tax Profile", priority: 50 },
//!         |_state, db, record_id| async move {
//!             let tin: Option<String> = sqlx::query_scalar("SELECT tin FROM …")
//!                 .bind(record_id).fetch_optional(&db).await?.flatten();
//!             Ok(format!("<p>TIN: {}</p>", tin.as_deref().unwrap_or("—")))
//!         },
//!     )]
//! }
//!
//! // In the OWNING module's detail handler:
//! let panels = render_record_panels(&state, &db, "contacts", id).await;
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;
use vortex_common::VortexResult;

use crate::state::AppState;

/// Where a panel attaches and how it is titled/ordered.
#[derive(Debug, Clone)]
pub struct RecordPanelDef {
    /// The owning module's model name (its detail page's identifier,
    /// conventionally the table name, e.g. `"contacts"`).
    pub model: &'static str,
    /// Card title rendered above the panel body.
    pub title: &'static str,
    /// Lower renders first.
    pub priority: i32,
}

/// Boxed async renderer: `(state, tenant db, record id) → inner HTML`.
pub type PanelHandler = Arc<
    dyn Fn(Arc<AppState>, PgPool, Uuid) -> Pin<Box<dyn Future<Output = VortexResult<String>> + Send>>
        + Send
        + Sync,
>;

pub struct RecordPanel {
    pub def: RecordPanelDef,
    pub handler: PanelHandler,
}

impl RecordPanel {
    /// Wrap a plain async closure into a `RecordPanel`.
    pub fn new<F, Fut>(def: RecordPanelDef, handler: F) -> Self
    where
        F: Fn(Arc<AppState>, PgPool, Uuid) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = VortexResult<String>> + Send + 'static,
    {
        Self {
            def,
            handler: Arc::new(move |state, db, id| Box::pin(handler(state, db, id))),
        }
    }
}

/// Render every registered plugin's panels for `model`, wrapped in the
/// standard card chrome, concatenated in priority order. Returns an
/// empty string when nothing contributes.
pub async fn render_record_panels(
    state: &Arc<AppState>,
    db: &PgPool,
    model: &str,
    record_id: Uuid,
) -> String {
    let mut panels: Vec<&RecordPanel> = Vec::new();
    let contributed: Vec<Vec<RecordPanel>> = state
        .plugin_registry
        .plugins_iter()
        .map(|p| p.record_panels())
        .collect();
    for list in &contributed {
        for panel in list {
            if panel.def.model == model {
                panels.push(panel);
            }
        }
    }
    panels.sort_by_key(|p| p.def.priority);
    let mut out = String::new();
    for panel in panels {
        match (panel.handler)(state.clone(), db.clone(), record_id).await {
            Ok(body) => out.push_str(&format!(
                r#"<div class="card bg-base-100 shadow mt-4"><div class="card-body p-4">
<h2 class="font-bold mb-2">{}</h2>{body}</div></div>"#,
                crate::html_escape(panel.def.title),
            )),
            Err(e) => {
                warn!(model, title = panel.def.title, "record panel failed: {e}");
            }
        }
    }
    out
}
