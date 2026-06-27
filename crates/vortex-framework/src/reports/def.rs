//! [`ReportDef`] — plugin-declared report, matching the pattern the
//! scheduler uses for background jobs.
//!
//! Plugins contribute reports via `Plugin::reports()`; the host
//! assembles them into a [`crate::reports::ReportRegistry`] at
//! startup and routes render requests through the registry by code.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use vortex_common::VortexResult;

use crate::state::AppState;

use super::format::{ReportFormat, ReportOutput};

/// Query parameters passed to a report handler.
///
/// The format is resolved from `?format=` (defaulting to HTML) and
/// the remaining key/value query pairs are passed through verbatim
/// so the handler can filter by date range, filter by entity, etc.
/// Plugins that need richer request shapes (JSON bodies, POST, file
/// uploads) should either (a) accept everything via query params for
/// now, or (b) register their own custom route that calls into the
/// registry directly rather than going through the generic
/// `/reports/:code` endpoint.
#[derive(Debug, Clone)]
pub struct ReportParams {
    pub format: ReportFormat,
    pub query: HashMap<String, String>,
}

impl ReportParams {
    pub fn new(format: ReportFormat) -> Self {
        Self {
            format,
            query: HashMap::new(),
        }
    }

    /// Convenience accessor: get a query param by key, or `None`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.query.get(key).map(String::as_str)
    }
}

/// The boxed async handler signature. Constructed by
/// [`ReportDef::new`] from an ordinary `async fn(Arc<AppState>,
/// ReportParams) -> VortexResult<ReportOutput>` closure.
pub type ReportHandler = Arc<
    dyn Fn(Arc<AppState>, ReportParams) -> Pin<Box<dyn Future<Output = VortexResult<ReportOutput>> + Send>>
        + Send
        + Sync,
>;

/// A plugin-declared report.
#[derive(Clone)]
pub struct ReportDef {
    /// Globally-unique report code, conventionally
    /// `<plugin_technical_name>.<report_name>` — e.g.
    /// `eam.work_order_summary`, `sales.invoice`.
    pub code: &'static str,
    /// Human-readable display name, shown in UI listings.
    pub name: &'static str,
    /// One-line description shown in listings and in the audit event.
    pub description: &'static str,
    /// The formats this handler knows how to render. The HTTP route
    /// validates the requested format against this list and returns
    /// `400 Bad Request` if the caller asks for something the handler
    /// cannot produce.
    pub formats: Vec<ReportFormat>,
    /// The handler closure.
    pub handler: ReportHandler,
}

impl ReportDef {
    /// Wrap an async closure into a `ReportDef`.
    ///
    /// ```rust,ignore
    /// use vortex_framework::reports::{ReportDef, ReportFormat, ReportOutput};
    ///
    /// ReportDef::new(
    ///     "eam.wo_summary",
    ///     "Work Order Summary",
    ///     "Printable summary of a work order for the field crew",
    ///     vec![ReportFormat::Html, ReportFormat::Csv],
    ///     |state, params| async move {
    ///         let id = params.get("id").ok_or_else(|| /* ... */)?;
    ///         // ... query, render ...
    ///         Ok(ReportOutput::html("wo.html", body))
    ///     },
    /// )
    /// ```
    pub fn new<F, Fut>(
        code: &'static str,
        name: &'static str,
        description: &'static str,
        formats: Vec<ReportFormat>,
        handler: F,
    ) -> Self
    where
        F: Fn(Arc<AppState>, ReportParams) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = VortexResult<ReportOutput>> + Send + 'static,
    {
        Self {
            code,
            name,
            description,
            formats,
            handler: Arc::new(move |state, params| Box::pin(handler(state, params))),
        }
    }

    /// Whether this report can be rendered in the given format.
    pub fn supports(&self, format: ReportFormat) -> bool {
        self.formats.contains(&format)
    }
}

impl std::fmt::Debug for ReportDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportDef")
            .field("code", &self.code)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("formats", &self.formats)
            .field("handler", &"<fn>")
            .finish()
    }
}
