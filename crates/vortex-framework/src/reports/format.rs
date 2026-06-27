//! [`ReportFormat`] and [`ReportOutput`] — the value types that
//! every report handler produces and every route consumer reads.
//!
//! Formats are an enum rather than a string so the registry can
//! validate "does this report support the requested format" at
//! render time without plugins having to declare MIME strings.

use serde::{Deserialize, Serialize};

/// Output format for a report render.
///
/// Today's set covers the three cases that can be produced with
/// zero native dependencies: HTML (Askama templates or hand-built
/// strings), CSV (the `csv` crate), and JSON (serde_json). PDF and
/// XLSX are deliberately **not** in core — they pull in heavyweight
/// dependencies (wkhtmltopdf, headless browsers, or native PDF
/// encoders) and belong in separate report-backend plugins that
/// wrap the core primitive.
///
/// If a plugin needs PDF today, the best path is:
///
/// 1. Have the report handler generate well-styled HTML with
///    `@media print` rules in the stylesheet.
/// 2. Let the user "Print → Save as PDF" from the browser.
///
/// That covers the 80% case without coupling core to a PDF engine.
/// A future `vortex-report-pdf` plugin can register a wrapper that
/// accepts HTML input and produces PDF bytes via typst, a headless
/// browser, or any other backend — without touching this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    /// Rendered HTML. Served with `text/html; charset=utf-8`.
    Html,
    /// Comma-separated values for spreadsheet / ETL consumers.
    Csv,
    /// JSON for API consumers and machine readers.
    Json,
}

impl ReportFormat {
    /// Stable lowercase code used in URLs (`?format=html`) and in
    /// audit payloads. Must never change for a given variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReportFormat::Html => "html",
            ReportFormat::Csv => "csv",
            ReportFormat::Json => "json",
        }
    }

    /// Parse a format from its URL string. Returns `None` for
    /// unknown formats — the caller decides whether to 400 or
    /// default to HTML.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "html" | "htm" => Some(ReportFormat::Html),
            "csv" => Some(ReportFormat::Csv),
            "json" => Some(ReportFormat::Json),
            _ => None,
        }
    }

    /// Default Content-Type header for this format. Handlers that
    /// need to override (e.g. XML-in-HTML, JSONL) can set a custom
    /// `content_type` on the [`ReportOutput`] directly.
    pub fn content_type(&self) -> &'static str {
        match self {
            ReportFormat::Html => "text/html; charset=utf-8",
            ReportFormat::Csv => "text/csv; charset=utf-8",
            ReportFormat::Json => "application/json",
        }
    }

    /// File extension for the `filename=` part of Content-Disposition.
    pub fn extension(&self) -> &'static str {
        match self {
            ReportFormat::Html => "html",
            ReportFormat::Csv => "csv",
            ReportFormat::Json => "json",
        }
    }
}

/// The output of a single report render.
///
/// Handlers construct this directly or via the convenience helpers
/// ([`ReportOutput::html`], [`ReportOutput::csv`], [`ReportOutput::json`]),
/// and the HTTP route turns it into an `axum::Response` with the
/// right headers. Callers can also consume [`ReportOutput`] directly
/// without going through HTTP — e.g. to attach the bytes to an email
/// or archive them in a document store.
#[derive(Debug, Clone)]
pub struct ReportOutput {
    /// Which format these bytes are in. Mostly informational for
    /// callers — the `content_type` and `filename` fields below are
    /// what the HTTP layer actually uses.
    pub format: ReportFormat,
    /// MIME type for the response. Defaults to
    /// [`ReportFormat::content_type`] but handlers can override
    /// (e.g. set a `charset` different from utf-8).
    pub content_type: String,
    /// Suggested filename (without directory). Lands in the
    /// `Content-Disposition: attachment; filename="..."` header.
    /// For HTML reports viewed inline this is still useful as the
    /// "save as" default.
    pub filename: String,
    /// The rendered bytes.
    pub bytes: Vec<u8>,
}

impl ReportOutput {
    /// Build an HTML report output from a string body. The body is
    /// typically produced by an Askama template; no framing or
    /// wrapping is added — what the handler passes in is what the
    /// client receives.
    pub fn html(filename: impl Into<String>, body: impl Into<String>) -> Self {
        let body: String = body.into();
        Self {
            format: ReportFormat::Html,
            content_type: ReportFormat::Html.content_type().to_string(),
            filename: filename.into(),
            bytes: body.into_bytes(),
        }
    }

    /// Build a CSV report output from raw bytes. Handlers typically
    /// write via the `csv` crate into a `Vec<u8>` and pass it here.
    pub fn csv(filename: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            format: ReportFormat::Csv,
            content_type: ReportFormat::Csv.content_type().to_string(),
            filename: filename.into(),
            bytes,
        }
    }

    /// Build a JSON report output from any `serde_json::Value` or
    /// serializable type. Uses pretty-printing so the output is
    /// readable when a human hits the URL in a browser.
    pub fn json<T: serde::Serialize>(
        filename: impl Into<String>,
        value: &T,
    ) -> Result<Self, serde_json::Error> {
        let bytes = serde_json::to_vec_pretty(value)?;
        Ok(Self {
            format: ReportFormat::Json,
            content_type: ReportFormat::Json.content_type().to_string(),
            filename: filename.into(),
            bytes,
        })
    }

    /// Byte length of the rendered output. Used for the
    /// `Content-Length` header and for the audit payload's
    /// `byte_count` field.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_roundtrip() {
        for f in [ReportFormat::Html, ReportFormat::Csv, ReportFormat::Json] {
            assert_eq!(ReportFormat::from_str(f.as_str()), Some(f));
        }
    }

    #[test]
    fn format_parse_is_case_insensitive() {
        assert_eq!(ReportFormat::from_str("HTML"), Some(ReportFormat::Html));
        assert_eq!(ReportFormat::from_str("Csv"), Some(ReportFormat::Csv));
        assert_eq!(ReportFormat::from_str("JSON"), Some(ReportFormat::Json));
        assert_eq!(ReportFormat::from_str("htm"), Some(ReportFormat::Html));
    }

    #[test]
    fn format_parse_unknown_is_none() {
        assert!(ReportFormat::from_str("pdf").is_none());
        assert!(ReportFormat::from_str("xlsx").is_none());
        assert!(ReportFormat::from_str("").is_none());
    }

    #[test]
    fn content_types_are_expected_mimes() {
        assert!(ReportFormat::Html.content_type().starts_with("text/html"));
        assert!(ReportFormat::Csv.content_type().starts_with("text/csv"));
        assert_eq!(ReportFormat::Json.content_type(), "application/json");
    }

    #[test]
    fn extensions_match_formats() {
        assert_eq!(ReportFormat::Html.extension(), "html");
        assert_eq!(ReportFormat::Csv.extension(), "csv");
        assert_eq!(ReportFormat::Json.extension(), "json");
    }

    #[test]
    fn html_builder_sets_metadata() {
        let out = ReportOutput::html("report.html", "<h1>hello</h1>");
        assert_eq!(out.format, ReportFormat::Html);
        assert_eq!(out.filename, "report.html");
        assert_eq!(out.content_type, "text/html; charset=utf-8");
        assert_eq!(out.bytes, b"<h1>hello</h1>".to_vec());
        assert_eq!(out.len(), 14);
        assert!(!out.is_empty());
    }

    #[test]
    fn csv_builder_preserves_bytes_verbatim() {
        let bytes = b"a,b,c\n1,2,3\n".to_vec();
        let out = ReportOutput::csv("data.csv", bytes.clone());
        assert_eq!(out.format, ReportFormat::Csv);
        assert_eq!(out.bytes, bytes);
    }

    #[test]
    fn json_builder_pretty_prints() {
        let value = serde_json::json!({ "total": 42, "items": [1, 2, 3] });
        let out = ReportOutput::json("data.json", &value).unwrap();
        assert_eq!(out.format, ReportFormat::Json);
        let text = String::from_utf8(out.bytes).unwrap();
        // Pretty-printed JSON has newlines and indentation.
        assert!(text.contains('\n'));
        assert!(text.contains("  "));
        assert!(text.contains("\"total\""));
    }
}
