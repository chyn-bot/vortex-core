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

/// Who performed the save and on which tenant — passed through so
/// panel saves can write attributed, field-level history entries.
#[derive(Debug, Clone)]
pub struct PanelSaveCtx {
    pub user_id: Uuid,
    pub username: String,
    pub db_name: String,
}

/// Boxed async save hook: `(state, tenant db, record id, submitted
/// form pairs, actor context)`. Receives the OWNER form's full
/// submission — pick out your own fields and ignore the rest.
pub type PanelSaveHandler = Arc<
    dyn Fn(
            Arc<AppState>,
            PgPool,
            Uuid,
            Vec<(String, String)>,
            PanelSaveCtx,
        ) -> Pin<Box<dyn Future<Output = VortexResult<()>> + Send>>
        + Send
        + Sync,
>;

/// The `id` a host detail page gives its `<form>` element so panel
/// inputs can join it via the HTML `form="…"` attribute — one Save
/// button submits host fields and panel fields together.
pub const HOST_FORM_ID: &str = "record-form";

pub struct RecordPanel {
    pub def: RecordPanelDef,
    pub handler: PanelHandler,
    pub save: Option<PanelSaveHandler>,
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
            save: None,
        }
    }

    /// Attach a save hook. Render the panel's inputs with
    /// `form="record-form"` ([`HOST_FORM_ID`]) and the owner's single
    /// Save button will persist them through this hook.
    pub fn with_save<F, Fut>(mut self, save: F) -> Self
    where
        F: Fn(Arc<AppState>, PgPool, Uuid, Vec<(String, String)>, PanelSaveCtx) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: Future<Output = VortexResult<()>> + Send + 'static,
    {
        self.save = Some(Arc::new(move |state, db, id, pairs, ctx| {
            Box::pin(save(state, db, id, pairs, ctx))
        }));
        self
    }
}

/// Run every registered panel's save hook for `model` with the owner
/// form's submission. Called by the owning module's update handler
/// AFTER its own save. A failing hook is logged and does not abort the
/// others — the owner's save has already committed.
pub async fn handle_record_panel_saves(
    state: &Arc<AppState>,
    db: &PgPool,
    model: &str,
    record_id: Uuid,
    pairs: &[(String, String)],
    ctx: &PanelSaveCtx,
) {
    let contributed: Vec<Vec<RecordPanel>> = state
        .plugin_registry
        .plugins_iter()
        .map(|p| p.record_panels())
        .collect();
    for list in &contributed {
        for panel in list {
            if panel.def.model != model {
                continue;
            }
            if let Some(save) = &panel.save {
                if let Err(e) = save(
                    state.clone(),
                    db.clone(),
                    record_id,
                    pairs.to_vec(),
                    ctx.clone(),
                )
                .await
                {
                    warn!(model, title = panel.def.title, "record panel save failed: {e}");
                }
            }
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
