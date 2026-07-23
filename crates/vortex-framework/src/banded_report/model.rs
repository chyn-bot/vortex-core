//! `ReportLayout` — the serde document for a banded, pixel-perfect report.
//!
//! Stored as JSONB in `ir_report_layout.document` and authored by the
//! Report Studio canvas. All fields carry `#[serde(default)]` so partial
//! documents (and forward-compatible additions) deserialize cleanly — the
//! same discipline as [`crate::print_layout::LayoutConfig`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ─── Root ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportLayout {
    /// Canvas + output unit: `pt` (default), `mm`, or `px`.
    #[serde(default = "d_unit")]
    pub unit: String,
    #[serde(default)]
    pub page: Page,
    #[serde(default)]
    pub dataset: Dataset,
    #[serde(default)]
    pub params: Vec<Param>,
    #[serde(default)]
    pub variables: Vec<Variable>,
    #[serde(default)]
    pub bands: Bands,
}

impl Default for ReportLayout {
    fn default() -> Self {
        Self {
            unit: d_unit(),
            page: Page::default(),
            dataset: Dataset::default(),
            params: Vec::new(),
            variables: Vec::new(),
            bands: Bands::default(),
        }
    }
}

impl ReportLayout {
    /// Convert a length in the document unit to CSS inches (Chromium PDF unit).
    pub fn to_inches(&self, v: f64) -> f64 {
        match self.unit.as_str() {
            "mm" => v / 25.4,
            "px" => v / 96.0,
            _ => v / 72.0, // pt
        }
    }
    /// The unit suffix used in emitted CSS (`pt`/`mm`/`px`).
    pub fn css_unit(&self) -> &str {
        match self.unit.as_str() {
            "mm" => "mm",
            "px" => "px",
            _ => "pt",
        }
    }
}

// ─── Page ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    #[serde(default = "d_a4")]
    pub size: String,
    #[serde(default = "d_portrait")]
    pub orientation: String,
    #[serde(default = "d_w")]
    pub width: f64,
    #[serde(default = "d_h")]
    pub height: f64,
    #[serde(default)]
    pub margin: Margin,
    #[serde(default = "d_one")]
    pub columns: u32,
    #[serde(default)]
    pub column_gap: f64,
}

impl Default for Page {
    fn default() -> Self {
        Self {
            size: d_a4(),
            orientation: d_portrait(),
            width: d_w(),
            height: d_h(),
            margin: Margin::default(),
            columns: 1,
            column_gap: 0.0,
        }
    }
}

impl Page {
    /// Usable content width between the left/right margins.
    pub fn content_width(&self) -> f64 {
        (self.width - self.margin.left - self.margin.right).max(0.0)
    }
    /// Number of detail columns, always ≥ 1.
    pub fn cols(&self) -> u32 {
        self.columns.max(1)
    }
    /// Width of a single detail column accounting for the gutters.
    pub fn column_width(&self) -> f64 {
        let c = self.cols() as f64;
        ((self.content_width() - (c - 1.0) * self.column_gap) / c).max(0.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Margin {
    #[serde(default = "d_margin")]
    pub top: f64,
    #[serde(default = "d_margin")]
    pub right: f64,
    #[serde(default = "d_margin")]
    pub bottom: f64,
    #[serde(default = "d_margin")]
    pub left: f64,
}

impl Default for Margin {
    fn default() -> Self {
        Self { top: d_margin(), right: d_margin(), bottom: d_margin(), left: d_margin() }
    }
}

// ─── Dataset ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Dataset {
    /// `ir_model.name` the report reads. Empty = static/no-data report.
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub sort: Vec<SortKey>,
    #[serde(default)]
    pub groups: Vec<Group>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortKey {
    pub field: String,
    #[serde(default = "d_asc")]
    pub dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Expression whose value defines the group boundary (e.g. `$F{partner}`).
    pub expr: String,
    /// Band key under `bands.groupHeaders` printed when the group opens.
    #[serde(default)]
    pub header: String,
    /// Band key under `bands.groupFooters` printed when the group closes.
    #[serde(default)]
    pub footer: String,
    /// Reprint the group header at the top of every continuation page.
    #[serde(default)]
    pub reprint: bool,
}

// ─── Params & variables ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Param {
    pub name: String,
    #[serde(rename = "type", default = "d_text")]
    pub kind: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    /// `sum | count | avg | min | max`.
    #[serde(default = "d_sum")]
    pub calc: String,
    /// Expression aggregated over the reset window.
    #[serde(default)]
    pub expr: String,
    /// `report` (default) | `page` | `group:<name>`.
    #[serde(default = "d_report")]
    pub reset: String,
}

// ─── Bands ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bands {
    #[serde(default)]
    pub title: Band,
    #[serde(default)]
    pub page_header: Band,
    #[serde(default)]
    pub column_header: Band,
    #[serde(default)]
    pub group_headers: BTreeMap<String, Band>,
    #[serde(default)]
    pub detail: Band,
    #[serde(default)]
    pub group_footers: BTreeMap<String, Band>,
    #[serde(default)]
    pub column_footer: Band,
    #[serde(default)]
    pub page_footer: Band,
    #[serde(default)]
    pub summary: Band,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Band {
    #[serde(default)]
    pub height: f64,
    #[serde(default)]
    pub elements: Vec<Element>,
    /// Optional visibility expression for the whole band.
    #[serde(default, rename = "printWhen")]
    pub print_when: Option<String>,
}

// ─── Elements ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Element {
    #[serde(default)]
    pub id: String,
    /// `staticText | field | line | box | image | barcode | subreport`.
    #[serde(rename = "type", default = "d_field")]
    pub kind: String,
    #[serde(default)]
    pub x: f64,
    #[serde(default)]
    pub y: f64,
    #[serde(default)]
    pub w: f64,
    #[serde(default)]
    pub h: f64,
    /// Value expression for `field`/`barcode`/`image` (a URL or data expr).
    #[serde(default)]
    pub expr: Option<String>,
    /// Literal text for `staticText`.
    #[serde(default)]
    pub text: Option<String>,
    /// Per-element visibility expression.
    #[serde(default, rename = "printWhen")]
    pub print_when: Option<String>,
    #[serde(default)]
    pub style: Style,
    #[serde(default)]
    pub barcode: Option<Barcode>,
    #[serde(default)]
    pub subreport: Option<Subreport>,
}

impl Default for Element {
    fn default() -> Self {
        Self {
            id: String::new(),
            kind: d_field(),
            x: 0.0,
            y: 0.0,
            w: 100.0,
            h: 16.0,
            expr: None,
            text: None,
            print_when: None,
            style: Style::default(),
            barcode: None,
            subreport: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Style {
    #[serde(default = "d_font")]
    pub font: String,
    #[serde(default = "d_size")]
    pub size: f64,
    #[serde(default)]
    pub bold: bool,
    #[serde(default)]
    pub italic: bool,
    #[serde(default)]
    pub underline: bool,
    /// `left | center | right | justify`.
    #[serde(default = "d_left")]
    pub align: String,
    /// `top | middle | bottom`.
    #[serde(default = "d_middle")]
    pub valign: String,
    #[serde(default = "d_color")]
    pub color: String,
    #[serde(default)]
    pub bg: Option<String>,
    #[serde(default)]
    pub border: Border,
    /// Number/date format mask, e.g. `#,##0.00` or `yyyy-MM-dd`.
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default = "d_true")]
    pub wrap: bool,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            font: d_font(),
            size: d_size(),
            bold: false,
            italic: false,
            underline: false,
            align: d_left(),
            valign: d_middle(),
            color: d_color(),
            bg: None,
            border: Border::default(),
            format: None,
            wrap: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Border {
    #[serde(default)]
    pub top: f64,
    #[serde(default)]
    pub right: f64,
    #[serde(default)]
    pub bottom: f64,
    #[serde(default)]
    pub left: f64,
    #[serde(default = "d_border_color")]
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Barcode {
    /// `qr | code128 | ean13`.
    #[serde(default = "d_qr")]
    pub symbology: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subreport {
    /// `ir_report.code` of the child banded report.
    pub code: String,
    /// Maps child param name -> parent expression evaluated per detail row.
    #[serde(default)]
    pub param_map: BTreeMap<String, String>,
}

// ─── serde defaults ──────────────────────────────────────────────────────

fn d_unit() -> String {
    "pt".into()
}
fn d_a4() -> String {
    "A4".into()
}
fn d_portrait() -> String {
    "portrait".into()
}
fn d_w() -> f64 {
    595.0
}
fn d_h() -> f64 {
    842.0
}
fn d_margin() -> f64 {
    36.0
}
fn d_one() -> u32 {
    1
}
fn d_asc() -> String {
    "asc".into()
}
fn d_text() -> String {
    "text".into()
}
fn d_sum() -> String {
    "sum".into()
}
fn d_report() -> String {
    "report".into()
}
fn d_field() -> String {
    "field".into()
}
fn d_font() -> String {
    "Helvetica, Arial, sans-serif".into()
}
fn d_size() -> f64 {
    10.0
}
fn d_left() -> String {
    "left".into()
}
fn d_middle() -> String {
    "middle".into()
}
fn d_color() -> String {
    "#111111".into()
}
fn d_border_color() -> String {
    "#cccccc".into()
}
fn d_true() -> bool {
    true
}
fn d_qr() -> String {
    "qr".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_doc_deserializes_with_defaults() {
        let l: ReportLayout = serde_json::from_str("{}").unwrap();
        assert_eq!(l.unit, "pt");
        assert_eq!(l.page.width, 595.0);
        assert_eq!(l.page.margin.top, 36.0);
        assert_eq!(l.page.cols(), 1);
    }

    #[test]
    fn unit_conversion() {
        let mut l = ReportLayout::default();
        l.unit = "mm".into();
        assert!((l.to_inches(25.4) - 1.0).abs() < 1e-9);
        l.unit = "px".into();
        assert!((l.to_inches(96.0) - 1.0).abs() < 1e-9);
        l.unit = "pt".into();
        assert!((l.to_inches(72.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn element_type_alias() {
        let e: Element = serde_json::from_str(r#"{"type":"field","expr":"$F{name}"}"#).unwrap();
        assert_eq!(e.kind, "field");
        assert_eq!(e.expr.as_deref(), Some("$F{name}"));
    }

    #[test]
    fn content_and_column_width() {
        let mut p = Page::default();
        p.width = 200.0;
        p.margin.left = 10.0;
        p.margin.right = 10.0;
        p.columns = 2;
        p.column_gap = 20.0;
        assert_eq!(p.content_width(), 180.0);
        assert_eq!(p.column_width(), 80.0); // (180 - 20) / 2
    }
}
