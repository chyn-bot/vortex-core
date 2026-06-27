//! Platform report engine — declarative, plugin-contributed reports
//! with a generic HTTP endpoint, an audit-logged render pipeline,
//! and three zero-dependency output formats.
//!
//! Every customer-facing ERP eventually needs to show structured
//! data in a format other than an interactive HTML table:
//! invoices, delivery notes, work-order printouts, inspection
//! reports, end-of-period summaries, data exports for ETL. This
//! module is the primitive that lets plugins declare those reports
//! once and get:
//!
//! - a central registry the host builds at startup from every
//!   plugin's `Plugin::reports()` contribution
//! - a standard HTTP endpoint `GET /reports/:code?format=…` that
//!   dispatches by code, validates the requested format, runs the
//!   handler, and writes a `BulkExport` audit event for every
//!   successful render
//! - clean separation between "what the report produces" (the
//!   handler's [`ReportOutput`]) and "how it gets delivered" (the
//!   HTTP route, an email attachment, a scheduled batch) so the
//!   same handler works from every consumer
//!
//! ## Scope decisions
//!
//! **In core**: HTML, CSV, JSON. These three formats are producible
//! with zero native dependencies — HTML is string concatenation or
//! Askama, CSV uses the `csv` crate (which plugins pull in as
//! needed, not a core dep), JSON uses the `serde_json` that's
//! already everywhere.
//!
//! **Deferred to extension plugins**: PDF and XLSX. Both require
//! substantial native dependencies (wkhtmltopdf / headless browser /
//! typst for PDF; `rust_xlsxwriter` or native OOXML for XLSX) with
//! different licensing, binary size, and security surfaces. A
//! future `vortex-report-pdf` plugin can wrap one of those backends
//! and register as another consumer of the HTML output from this
//! module — without forcing every Vortex deployment to carry the
//! dependency.
//!
//! **The "browser print → Save as PDF" workaround** covers the 80%
//! case for internal reports today. Plugins that generate
//! HTML with `@media print` stylesheets produce reports that look
//! right when a user hits Ctrl+P. Regulated customer-facing
//! artifacts (legal invoices, tax filings) that need a guaranteed
//! PDF format can wait for the extension plugin.
//!
//! ## Usage from a plugin
//!
//! ```rust,ignore
//! use vortex_framework::reports::{ReportDef, ReportFormat, ReportOutput};
//! use vortex_framework::Plugin;
//!
//! impl Plugin for MyPlugin {
//!     // … other methods …
//!
//!     fn reports(&self) -> Vec<ReportDef> {
//!         vec![
//!             ReportDef::new(
//!                 "myplugin.summary",
//!                 "Daily summary",
//!                 "Rolling 24-hour summary of activity",
//!                 vec![ReportFormat::Html, ReportFormat::Csv, ReportFormat::Json],
//!                 |state, params| async move {
//!                     let rows = load_summary_rows(&state.db).await?;
//!                     match params.format {
//!                         ReportFormat::Html => {
//!                             let body = render_html(&rows);
//!                             Ok(ReportOutput::html("summary.html", body))
//!                         }
//!                         ReportFormat::Csv => {
//!                             let bytes = encode_csv(&rows)?;
//!                             Ok(ReportOutput::csv("summary.csv", bytes))
//!                         }
//!                         ReportFormat::Json => {
//!                             ReportOutput::json("summary.json", &rows)
//!                                 .map_err(|e| VortexError::Serialization(e.to_string()))
//!                         }
//!                     }
//!                 },
//!             ),
//!         ]
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{info, warn};

use vortex_common::VortexResult;

use crate::state::AppState;

pub mod def;
pub mod format;
pub mod routes;

pub use def::{ReportDef, ReportHandler, ReportParams};
pub use format::{ReportFormat, ReportOutput};
pub use routes::reports_routes;

/// The central registry of plugin-contributed reports. Built at
/// startup from every plugin's `Plugin::reports()` contribution and
/// stored on [`AppState`] so the HTTP route and any direct
/// consumer (scheduled email, export script, debug CLI) can look
/// reports up by code.
pub struct ReportRegistry {
    reports: HashMap<String, ReportDef>,
}

impl ReportRegistry {
    /// Build a registry from the aggregated report defs of every
    /// registered plugin. Collisions — two plugins contributing
    /// the same report code — are logged as a warning and the
    /// first registration wins. Plugins should namespace their
    /// report codes with their technical name (e.g.
    /// `crm.lead_summary`) so collisions cannot happen in
    /// practice.
    pub fn new(defs: Vec<ReportDef>) -> Self {
        let mut reports: HashMap<String, ReportDef> = HashMap::new();
        for def in defs {
            let code = def.code.to_string();
            if reports.contains_key(&code) {
                warn!(
                    code = %code,
                    "duplicate report code — keeping first registration"
                );
                continue;
            }
            info!(
                code = %code,
                name = %def.name,
                formats = ?def.formats,
                "registered report"
            );
            reports.insert(code, def);
        }
        Self { reports }
    }

    /// Look up a report by its code. Returns `None` if no report
    /// with that code is registered.
    pub fn get(&self, code: &str) -> Option<&ReportDef> {
        self.reports.get(code)
    }

    /// Number of reports registered.
    pub fn len(&self) -> usize {
        self.reports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.reports.is_empty()
    }

    /// Every registered report, in stable order (by code). Useful
    /// for admin listings and the "which reports exist" debug
    /// command.
    pub fn list(&self) -> Vec<&ReportDef> {
        let mut out: Vec<&ReportDef> = self.reports.values().collect();
        out.sort_by_key(|r| r.code);
        out
    }

    /// Filter registered reports by format support.
    pub fn list_by_format(&self, format: ReportFormat) -> Vec<&ReportDef> {
        let mut out: Vec<&ReportDef> = self
            .reports
            .values()
            .filter(|r| r.supports(format))
            .collect();
        out.sort_by_key(|r| r.code);
        out
    }
}

impl std::fmt::Debug for ReportRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportRegistry")
            .field("count", &self.reports.len())
            .finish()
    }
}

/// Render a report directly by code, bypassing HTTP. Used by
/// scheduled-task consumers, email attachments, and any plugin
/// that wants to stream a report into a different output channel.
///
/// Errors if the code is unknown, if the format is unsupported,
/// or if the handler itself returns an error. Audit logging is
/// **not** performed here — only the HTTP route logs `BulkExport`
/// events. Callers that need audit trails should log their own
/// event (with the consumer context) after this returns.
pub async fn render_report(
    state: &Arc<AppState>,
    code: &str,
    params: ReportParams,
) -> VortexResult<ReportOutput> {
    use vortex_common::VortexError;

    let def = state
        .reports
        .get(code)
        .ok_or_else(|| VortexError::ValidationFailed(format!("unknown report: {code}")))?
        .clone();

    if !def.supports(params.format) {
        return Err(VortexError::ValidationFailed(format!(
            "report '{code}' does not support format '{}'",
            params.format.as_str()
        )));
    }

    (def.handler)(state.clone(), params).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_def(code: &'static str, formats: Vec<ReportFormat>) -> ReportDef {
        ReportDef::new(
            code,
            "test",
            "test report",
            formats,
            |_state, _params| async move {
                Ok(ReportOutput::html("test.html", "<h1>hello</h1>"))
            },
        )
    }

    #[test]
    fn registry_stores_reports_by_code() {
        let r = ReportRegistry::new(vec![
            noop_def("plugin.a", vec![ReportFormat::Html]),
            noop_def("plugin.b", vec![ReportFormat::Html, ReportFormat::Csv]),
        ]);
        assert_eq!(r.len(), 2);
        assert!(r.get("plugin.a").is_some());
        assert!(r.get("plugin.b").is_some());
        assert!(r.get("plugin.c").is_none());
    }

    #[test]
    fn registry_deduplicates_colliding_codes_first_wins() {
        let r = ReportRegistry::new(vec![
            noop_def("plugin.dup", vec![ReportFormat::Html]),
            noop_def("plugin.dup", vec![ReportFormat::Csv]),
        ]);
        assert_eq!(r.len(), 1);
        // First registration wins — HTML support remains, CSV lost.
        let def = r.get("plugin.dup").unwrap();
        assert!(def.supports(ReportFormat::Html));
        assert!(!def.supports(ReportFormat::Csv));
    }

    #[test]
    fn registry_list_is_stable_order() {
        let r = ReportRegistry::new(vec![
            noop_def("plugin.b", vec![ReportFormat::Html]),
            noop_def("plugin.a", vec![ReportFormat::Html]),
            noop_def("plugin.c", vec![ReportFormat::Html]),
        ]);
        let codes: Vec<&str> = r.list().iter().map(|d| d.code).collect();
        assert_eq!(codes, vec!["plugin.a", "plugin.b", "plugin.c"]);
    }

    #[test]
    fn registry_filters_by_format_support() {
        let r = ReportRegistry::new(vec![
            noop_def("plugin.html_only", vec![ReportFormat::Html]),
            noop_def("plugin.csv_and_html", vec![ReportFormat::Html, ReportFormat::Csv]),
            noop_def("plugin.json_only", vec![ReportFormat::Json]),
        ]);

        let html = r.list_by_format(ReportFormat::Html);
        assert_eq!(html.len(), 2);
        assert_eq!(html[0].code, "plugin.csv_and_html");
        assert_eq!(html[1].code, "plugin.html_only");

        let csv = r.list_by_format(ReportFormat::Csv);
        assert_eq!(csv.len(), 1);
        assert_eq!(csv[0].code, "plugin.csv_and_html");

        let json = r.list_by_format(ReportFormat::Json);
        assert_eq!(json.len(), 1);
        assert_eq!(json[0].code, "plugin.json_only");
    }

    #[test]
    fn report_def_supports_checks_format_list() {
        let def = noop_def("x", vec![ReportFormat::Html, ReportFormat::Csv]);
        assert!(def.supports(ReportFormat::Html));
        assert!(def.supports(ReportFormat::Csv));
        assert!(!def.supports(ReportFormat::Json));
    }

    #[test]
    fn empty_registry_is_empty() {
        let r = ReportRegistry::new(vec![]);
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.list().is_empty());
    }
}
