//! User-customisable **print layouts** for transactional documents.
//!
//! Odoo-style "document layout" + per-report template, built on primitives
//! already in the tree:
//!
//! * **Branding** ([`DocLayout`]) — logo (FileStore `company/logo`), brand
//!   colour, font, footer and paper size, shared by every printed document.
//!   Edited at `/settings/document-layout`.
//! * **Per-document template** ([`doc_print_templates`]) — an optional QWeb
//!   body for a document type (e.g. `sales.quotation`). When absent, the
//!   plugin's built-in [`PrintDocType::default_template`] is used. Edited at
//!   `/settings/print-templates`.
//!
//! The template engine is the existing sandboxed one in
//! [`crate::user_reports::render_template`] — same `{{ }}` / `{% for %}` /
//! `{% if %}` syntax, no new evaluator, no code execution. A document renders
//! by passing its **line items** as the iterable records and its header /
//! party / totals as flat dotted globals (`doc.number`, `company.name`,
//! `totals.total`, …); [`render_document`] wraps the result in the branded
//! print chrome ([`render_doc_page`]).
//!
//! Plugins expose their document types (label + default template + the
//! variables available to authors) from [`crate::plugin::Plugin::print_docs`];
//! the host collects them into a [`PrintDocRegistry`] on `AppState`, which the
//! settings UI reads to list editable documents and offer "Load default".

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::ui::html_escape;

fn yes() -> bool {
    true
}

/// Shared branding for every printed document. One row per tenant DB (the
/// first row wins); missing columns fall back to [`DocLayout::default`].
#[derive(Debug, Clone)]
pub struct DocLayout {
    pub brand_color: String,
    pub font_family: String,
    pub footer_html: String,
    pub paper_size: String,
}

impl Default for DocLayout {
    fn default() -> Self {
        DocLayout {
            brand_color: "#0f3460".to_string(),
            font_family: "Helvetica, Arial, sans-serif".to_string(),
            footer_html: String::new(),
            paper_size: "A4".to_string(),
        }
    }
}

impl DocLayout {
    /// Load the branding row, or defaults when none has been saved yet.
    pub async fn load(db: &PgPool) -> DocLayout {
        let row = sqlx::query(
            "SELECT brand_color, font_family, footer_html, paper_size \
             FROM doc_layout ORDER BY updated_at DESC LIMIT 1",
        )
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
        match row {
            Some(r) => DocLayout {
                brand_color: r.try_get("brand_color").unwrap_or_else(|_| "#0f3460".into()),
                font_family: r
                    .try_get("font_family")
                    .unwrap_or_else(|_| "Helvetica, Arial, sans-serif".into()),
                footer_html: r.try_get("footer_html").unwrap_or_default(),
                paper_size: r.try_get("paper_size").unwrap_or_else(|_| "A4".into()),
            },
            None => DocLayout::default(),
        }
    }

    /// Upsert the single branding row.
    pub async fn save(&self, db: &PgPool, user: Option<Uuid>) -> Result<(), sqlx::Error> {
        let existing: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM doc_layout ORDER BY updated_at DESC LIMIT 1")
                .fetch_optional(db)
                .await?;
        let paper = if self.paper_size == "Letter" { "Letter" } else { "A4" };
        match existing {
            Some(id) => {
                sqlx::query(
                    "UPDATE doc_layout SET brand_color=$1, font_family=$2, footer_html=$3, \
                     paper_size=$4, updated_at=now(), updated_by=$5 WHERE id=$6",
                )
                .bind(&self.brand_color)
                .bind(&self.font_family)
                .bind(&self.footer_html)
                .bind(paper)
                .bind(user)
                .bind(id)
                .execute(db)
                .await?;
            }
            None => {
                sqlx::query(
                    "INSERT INTO doc_layout (brand_color, font_family, footer_html, paper_size, updated_by) \
                     VALUES ($1,$2,$3,$4,$5)",
                )
                .bind(&self.brand_color)
                .bind(&self.font_family)
                .bind(&self.footer_html)
                .bind(paper)
                .bind(user)
                .execute(db)
                .await?;
            }
        }
        Ok(())
    }
}

/// A printable document type contributed by a plugin. Registered from
/// [`crate::plugin::Plugin::print_docs`]; surfaced in the settings UI.
#[derive(Debug, Clone)]
pub struct PrintDocType {
    /// Stable key, e.g. `"sales.quotation"`.
    pub doc_type: String,
    /// Human label, e.g. `"Quotation"`.
    pub label: String,
    /// Built-in QWeb body used when no custom template is saved. Also what
    /// "Load default" offers in the editor.
    pub default_template: String,
    /// `(name, description)` pairs documenting the variables a template author
    /// may use — rendered as a reference table in the editor.
    pub variables: Vec<(String, String)>,
    /// Synthetic header/party/totals globals used to render the editor's live
    /// preview (so a template can be previewed without a real record).
    pub sample_globals: BTreeMap<String, String>,
    /// Synthetic line records for the live preview.
    pub sample_lines: Vec<BTreeMap<String, String>>,
    /// When present, the document supports the **Visual** (no-code) editor:
    /// this is the structured starting point that compiles — via
    /// [`build_template`] — to the same layout as [`Self::default_template`].
    /// `None` means the document is HTML-template-only (advanced editor).
    pub default_config: Option<LayoutConfig>,
}

/// One line-item column in a [`LayoutConfig`]. The `key` is fixed by the plugin
/// (it names a `line.<key>` field); the visual editor only lets a user toggle
/// `show` and rename `label`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutColumn {
    pub key: String,
    pub label: String,
    #[serde(default = "yes")]
    pub show: bool,
    #[serde(default)]
    pub numeric: bool,
    #[serde(default)]
    pub mono: bool,
}

/// Structured, no-code description of a transactional document's layout. Edited
/// through the Visual print-template editor (toggles + labels), then compiled
/// to a QWeb body by [`build_template`] and stored next to that body so the
/// form can be reopened. Every field maps to one control in the editor.
///
/// The compiled template reads the standard document globals (`doc.*`,
/// `company.*`, `customer.*`, `totals.*`, `currency`) and iterates `lines`, so
/// any document type that supplies those (quotation, invoice, delivery, …) can
/// share this one config shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutConfig {
    pub title: String,
    #[serde(default = "yes")]
    pub show_logo: bool,
    #[serde(default = "yes")]
    pub show_company_address: bool,
    #[serde(default = "yes")]
    pub show_company_reg: bool,
    #[serde(default = "yes")]
    pub show_customer: bool,
    #[serde(default)]
    pub customer_label: String,
    #[serde(default = "yes")]
    pub show_headline: bool,
    #[serde(default = "yes")]
    pub show_summary: bool,
    #[serde(default = "yes")]
    pub show_number: bool,
    #[serde(default = "yes")]
    pub show_date: bool,
    #[serde(default = "yes")]
    pub show_validity: bool,
    #[serde(default)]
    pub validity_label: String,
    #[serde(default)]
    pub columns: Vec<LayoutColumn>,
    #[serde(default = "yes")]
    pub show_subtotal: bool,
    #[serde(default = "yes")]
    pub show_tax: bool,
    #[serde(default)]
    pub subtotal_label: String,
    #[serde(default)]
    pub tax_label: String,
    #[serde(default)]
    pub total_label: String,
    #[serde(default = "yes")]
    pub show_notes: bool,
    #[serde(default)]
    pub notes_label: String,
    #[serde(default = "yes")]
    pub show_signatures: bool,
    #[serde(default)]
    pub sign_left: String,
    #[serde(default)]
    pub sign_right: String,
}

impl LayoutConfig {
    /// The canonical starting layout for a priced transactional document: logo
    /// + company + bill-to header, a six-column line table (code / description
    /// / qty / unit price / tax / amount), subtotal-tax-total block, notes and
    /// a two-party signature strip. Callers pass their own document title.
    pub fn transactional(title: &str) -> Self {
        let col = |key: &str, label: &str, numeric: bool, mono: bool| LayoutColumn {
            key: key.to_string(),
            label: label.to_string(),
            show: true,
            numeric,
            mono,
        };
        LayoutConfig {
            title: title.to_string(),
            show_logo: true,
            show_company_address: true,
            show_company_reg: true,
            show_customer: true,
            customer_label: "To".to_string(),
            show_headline: true,
            show_summary: true,
            show_number: true,
            show_date: true,
            show_validity: true,
            validity_label: "Valid Until".to_string(),
            columns: vec![
                col("code", "Code", false, true),
                col("description", "Description", false, false),
                col("qty", "Qty", true, false),
                col("unit_price", "Unit Price", true, false),
                // Off by default; enable in the Visual editor to show discounts.
                LayoutColumn { key: "discount".into(), label: "Disc.".into(), show: false, numeric: true, mono: false },
                col("tax", "Tax", false, false),
                col("amount", "Amount", true, false),
            ],
            show_subtotal: true,
            show_tax: true,
            subtotal_label: "Subtotal".to_string(),
            tax_label: "Tax".to_string(),
            total_label: "Total".to_string(),
            show_notes: true,
            notes_label: "Notes".to_string(),
            show_signatures: true,
            sign_left: "Issued by".to_string(),
            sign_right: "Accepted by (customer)".to_string(),
        }
    }
}

/// Neutralise a user-entered label before embedding it as **literal** text in a
/// generated template: HTML-escape (`< > & " '`) so it can't inject markup, and
/// disarm `{` / `}` so it can't smuggle in template directives when the
/// generated body is later rendered by the engine.
fn lit(s: &str) -> String {
    html_escape(s).replace('{', "&#123;").replace('}', "&#125;")
}

/// Compile a [`LayoutConfig`] into a QWeb body understood by
/// [`crate::user_reports::render_template`]. Section toggles become present /
/// absent markup; line columns become table cells over `line.<key>`. Column
/// `key`s come from the plugin (never user input), while all labels/titles are
/// passed through [`lit`] so nothing a user types can break out of the layout.
pub fn build_template(cfg: &LayoutConfig) -> String {
    let mut s = String::new();
    s.push_str("{% if doc.watermark %}<div class=\"watermark\">{{ doc.watermark }}</div>{% endif %}\n");
    // ---- header: seller + document meta ----
    s.push_str("<div class=\"head\">\n  <div class=\"seller\">\n");
    if cfg.show_logo {
        s.push_str("    {% if company.logo %}<img class=\"logo\" src=\"{{ company.logo }}\"/>{% endif %}\n");
    }
    s.push_str("    <p class=\"name\">{{ company.name }}</p>\n");
    if cfg.show_company_address {
        s.push_str("    {% if company.addr1 %}<p>{{ company.addr1 }}</p>{% endif %}\n");
        s.push_str("    {% if company.addr2 %}<p>{{ company.addr2 }}</p>{% endif %}\n");
        s.push_str("    {% if company.city_line %}<p>{{ company.city_line }}</p>{% endif %}\n");
        s.push_str("    <p>{{ company.phone }} {{ company.email }}</p>\n");
    }
    if cfg.show_company_reg {
        s.push_str("    {% if company.reg %}<p class=\"label\">Reg No: {{ company.reg }}</p>{% endif %}\n");
    }
    s.push_str("  </div>\n  <div style=\"text-align:right\">\n");
    s.push_str(&format!("    <h1 class=\"doc-title\">{}</h1>\n", lit(&cfg.title)));
    s.push_str("    <table class=\"meta\" style=\"margin-left:auto\">\n");
    if cfg.show_number {
        s.push_str("      <tr><td class=\"label\">Number</td><td><b>{{ doc.number }}</b></td></tr>\n");
    }
    if cfg.show_date {
        s.push_str("      <tr><td class=\"label\">Date</td><td>{{ doc.date }}</td></tr>\n");
    }
    if cfg.show_validity {
        s.push_str(&format!(
            "      <tr><td class=\"label\">{}</td><td>{{{{ doc.validity }}}}</td></tr>\n",
            lit(&cfg.validity_label)
        ));
    }
    s.push_str("    </table>\n  </div>\n</div>\n");
    // ---- bill-to ----
    if cfg.show_customer {
        s.push_str("<div class=\"buyer\" style=\"margin-bottom:1em\">\n");
        s.push_str(&format!("  <p class=\"label\">{}</p>\n", lit(&cfg.customer_label)));
        s.push_str("  <p><b>{{ customer.name }}</b></p>\n");
        s.push_str("  {% if customer.street %}<p>{{ customer.street }}</p>{% endif %}\n");
        s.push_str("  {% if customer.street2 %}<p>{{ customer.street2 }}</p>{% endif %}\n");
        s.push_str("  {% if customer.city_line %}<p>{{ customer.city_line }}</p>{% endif %}\n");
        s.push_str("  <p>{{ customer.phone }} {{ customer.email }}</p>\n</div>\n");
    }
    // ---- headline / summary (Xero-style Title + intro) ----
    if cfg.show_headline {
        s.push_str("{% if doc.headline %}<h2 class=\"doc-headline\">{{ doc.headline }}</h2>{% endif %}\n");
    }
    if cfg.show_summary {
        s.push_str("{% if doc.summary %}<p class=\"doc-summary\">{{ doc.summary }}</p>{% endif %}\n");
    }
    // ---- line items ----
    let shown: Vec<&LayoutColumn> = cfg.columns.iter().filter(|c| c.show).collect();
    s.push_str("<table class=\"items\">\n  <thead><tr>");
    for c in &shown {
        let cls = if c.numeric { " class=\"num\"" } else { "" };
        s.push_str(&format!("<th{}>{}</th>", cls, lit(&c.label)));
    }
    let ncol = shown.len().max(1);
    s.push_str("</tr></thead>\n  <tbody>\n  {% for line in lines %}");
    // Odoo-style section / note rows span the whole table.
    s.push_str(&format!(
        "{{% if line.is_section %}}<tr class=\"sec-row\"><td colspan=\"{ncol}\">{{{{ line.text }}}}</td></tr>{{% endif %}}",
        ncol = ncol
    ));
    s.push_str(&format!(
        "{{% if line.is_note %}}<tr class=\"note-row\"><td colspan=\"{ncol}\">{{{{ line.text }}}}</td></tr>{{% endif %}}",
        ncol = ncol
    ));
    s.push_str("{% if line.is_line %}<tr>");
    for c in &shown {
        let mut classes: Vec<&str> = Vec::new();
        if c.numeric {
            classes.push("num");
        }
        if c.mono {
            classes.push("mono");
        }
        let cls = if classes.is_empty() {
            String::new()
        } else {
            format!(" class=\"{}\"", classes.join(" "))
        };
        // `key` is plugin-defined, never user input — safe to interpolate.
        s.push_str(&format!("<td{}>{{{{ line.{} }}}}</td>", cls, c.key));
    }
    s.push_str("</tr>{% endif %}{% endfor %}\n  </tbody>\n</table>\n");
    // ---- totals ----
    s.push_str("<table class=\"totals\">\n");
    if cfg.show_subtotal {
        // When a whole-quote discount applies, show the pre-discount subtotal,
        // the amount off, then the after-discount net; otherwise a plain
        // subtotal. `totals.discount` is empty (falsy) when there is none.
        s.push_str(&format!(
            "  {{% if totals.discount %}}<tr><td class=\"label\">{sub}</td><td class=\"num\">{{{{ totals.subtotal_pre }}}} {{{{ currency }}}}</td></tr>\n  \
             <tr><td class=\"label\">{{{{ totals.discount_label }}}}</td><td class=\"num\">- {{{{ totals.discount }}}} {{{{ currency }}}}</td></tr>\n  \
             <tr><td class=\"label\">After discount</td><td class=\"num\">{{{{ totals.untaxed }}}} {{{{ currency }}}}</td></tr>{{% else %}}<tr><td class=\"label\">{sub}</td><td class=\"num\">{{{{ totals.untaxed }}}} {{{{ currency }}}}</td></tr>{{% endif %}}\n",
            sub = lit(&cfg.subtotal_label)
        ));
    }
    if cfg.show_tax {
        s.push_str(&format!(
            "  <tr><td class=\"label\">{}</td><td class=\"num\">{{{{ totals.tax }}}} {{{{ currency }}}}</td></tr>\n",
            lit(&cfg.tax_label)
        ));
    }
    s.push_str(&format!(
        "  <tr class=\"grand\"><td>{}</td><td class=\"num\">{{{{ totals.total }}}} {{{{ currency }}}}</td></tr>\n</table>\n",
        lit(&cfg.total_label)
    ));
    // ---- notes ----
    if cfg.show_notes {
        s.push_str(&format!(
            "{{% if doc.note %}}<div class=\"note\"><span class=\"label\">{}</span><br/>{{{{ doc.note }}}}</div>{{% endif %}}\n",
            lit(&cfg.notes_label)
        ));
    }
    // ---- signatures ----
    if cfg.show_signatures {
        s.push_str(&format!(
            "<div class=\"accept\">\n  <div>{}<br><br>Name:<br>Date:</div>\n  <div>{}<br><br>Name, company stamp:<br>Date:</div>\n</div>\n",
            lit(&cfg.sign_left),
            lit(&cfg.sign_right)
        ));
    }
    s
}

/// Host-assembled registry of every plugin's [`PrintDocType`].
#[derive(Default)]
pub struct PrintDocRegistry {
    docs: HashMap<String, PrintDocType>,
    order: Vec<String>,
}

impl PrintDocRegistry {
    pub fn new(docs: Vec<PrintDocType>) -> Self {
        let mut map = HashMap::new();
        let mut order = Vec::new();
        for d in docs {
            if !map.contains_key(&d.doc_type) {
                order.push(d.doc_type.clone());
            }
            map.insert(d.doc_type.clone(), d);
        }
        PrintDocRegistry { docs: map, order }
    }

    pub fn get(&self, doc_type: &str) -> Option<&PrintDocType> {
        self.docs.get(doc_type)
    }

    /// All registered document types, in registration order.
    pub fn all(&self) -> Vec<&PrintDocType> {
        self.order.iter().filter_map(|k| self.docs.get(k)).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }
}

impl std::fmt::Debug for PrintDocRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrintDocRegistry")
            .field("count", &self.docs.len())
            .finish()
    }
}

/// Fetch a saved custom template body for a document type, if any.
pub async fn get_template(db: &PgPool, doc_type: &str) -> Option<String> {
    sqlx::query_scalar("SELECT body FROM doc_print_templates WHERE doc_type = $1")
        .bind(doc_type)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

/// Upsert a **hand-edited** custom template body. Clears any stored visual
/// config, because arbitrary HTML can't be reflected back into the visual
/// editor's form — the Visual tab then knows to warn before overwriting.
pub async fn save_template(
    db: &PgPool,
    doc_type: &str,
    body: &str,
    user: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO doc_print_templates (doc_type, body, updated_by) VALUES ($1,$2,$3) \
         ON CONFLICT (doc_type) DO UPDATE SET body = EXCLUDED.body, config = NULL, \
         updated_at = now(), updated_by = EXCLUDED.updated_by",
    )
    .bind(doc_type)
    .bind(body)
    .bind(user)
    .execute(db)
    .await?;
    Ok(())
}

/// The stored visual-editor state (JSON) for a document type, if it was last
/// saved through the Visual editor. `None` when never customised or when the
/// body was hand-edited in the HTML tab (which nulls the config).
pub async fn get_layout_config(db: &PgPool, doc_type: &str) -> Option<LayoutConfig> {
    let raw: Option<String> =
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT config::text FROM doc_print_templates WHERE doc_type = $1",
        )
        .bind(doc_type)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .flatten();
    raw.and_then(|s| serde_json::from_str::<LayoutConfig>(&s).ok())
}

/// Save a template produced by the Visual editor: store both the compiled QWeb
/// `body` (what the print path renders) and the structured `config` (what the
/// form reopens with). Kept in one transaction-free upsert.
pub async fn save_layout(
    db: &PgPool,
    doc_type: &str,
    cfg: &LayoutConfig,
    user: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    let body = build_template(cfg);
    let config_json = serde_json::to_string(cfg).unwrap_or_else(|_| "null".to_string());
    sqlx::query(
        "INSERT INTO doc_print_templates (doc_type, body, config, updated_by) \
         VALUES ($1,$2,$3::jsonb,$4) \
         ON CONFLICT (doc_type) DO UPDATE SET body = EXCLUDED.body, config = EXCLUDED.config, \
         updated_at = now(), updated_by = EXCLUDED.updated_by",
    )
    .bind(doc_type)
    .bind(&body)
    .bind(&config_json)
    .bind(user)
    .execute(db)
    .await?;
    Ok(())
}

/// Remove any custom template so the document falls back to the plugin default.
pub async fn clear_template(db: &PgPool, doc_type: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM doc_print_templates WHERE doc_type = $1")
        .bind(doc_type)
        .execute(db)
        .await?;
    Ok(())
}

/// Base stylesheet for printed documents, parameterised by branding. The
/// default templates use these classes so a colour/font change reflows every
/// document without editing markup.
pub fn base_css(layout: &DocLayout) -> String {
    let brand = sanitize_css_token(&layout.brand_color, "#0f3460");
    let font = sanitize_font(&layout.font_family);
    let paper = if layout.paper_size == "Letter" { "Letter" } else { "A4" };
    format!(
        r#":root {{ --brand: {brand}; }}
* {{ box-sizing: border-box; }}
body {{ font-family: {font}; color: #222; font-size: 13px; line-height: 1.4; max-width: 21cm; margin: 1.2cm auto; position: relative; padding: 0 0.4cm; }}
@page {{ size: {paper}; margin: 1.2cm 1.4cm; }}
@media print {{ body {{ max-width: none; margin: 0; padding: 0; }} .printbar {{ display: none !important; }} }}
h1, h2 {{ color: var(--brand); margin: 0; }}
.doc-title {{ font-size: 1.6em; letter-spacing: 0.06em; text-transform: uppercase; }}
.doc-headline {{ font-size: 1.15em; color: var(--brand); margin: 0.4em 0 0.2em; }}
.doc-summary {{ margin: 0 0 1em; font-size: 0.95em; color: #444; white-space: pre-line; }}
.head {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.4em; gap: 2em; }}
.head .logo {{ max-height: 64px; max-width: 220px; margin-bottom: 6px; }}
.seller p, .buyer p {{ margin: 1px 0; font-size: 0.9em; }}
.seller .name {{ font-size: 1.15em; font-weight: 700; color: var(--brand); }}
.label {{ font-size: 0.72em; text-transform: uppercase; letter-spacing: 0.08em; color: #888; }}
table.meta td {{ padding: 1px 8px 1px 0; font-size: 0.9em; border: none; }}
table.items {{ width: 100%; border-collapse: collapse; margin: 0.8em 0; }}
table.items th {{ background: var(--brand); color: #fff; text-align: left; padding: 6px 8px; font-size: 0.82em; text-transform: uppercase; letter-spacing: 0.04em; }}
table.items td {{ padding: 6px 8px; border-bottom: 1px solid #e5e5e5; font-size: 0.9em; white-space: pre-line; vertical-align: top; }}
table.items tr.sec-row td {{ font-weight: 700; color: var(--brand); background: #f4f5f7; padding-top: 10px; text-transform: none; }}
table.items tr.note-row td {{ font-style: italic; color: #555; }}
.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.mono {{ font-family: monospace; }}
table.totals {{ margin-left: auto; margin-top: 0.6em; }}
table.totals td {{ padding: 2px 8px; font-size: 0.95em; }}
table.totals tr.grand td {{ font-weight: 700; font-size: 1.1em; color: var(--brand); border-top: 2px solid var(--brand); }}
.accept {{ margin-top: 3em; display: flex; gap: 3em; }}
.accept div {{ flex: 1; border-top: 1px solid #333; padding-top: 0.4em; font-size: 0.82em; }}
.note {{ margin-top: 1.2em; font-size: 0.88em; white-space: pre-wrap; }}
.docfooter {{ margin-top: 2.4em; padding-top: 0.8em; border-top: 1px solid #ddd; font-size: 0.78em; color: #666; text-align: center; }}
.watermark {{ position: absolute; top: 34%; left: 12%; font-size: 5em; color: rgba(180,0,0,0.12); transform: rotate(-25deg); pointer-events: none; font-weight: 800; letter-spacing: 0.1em; }}
.printbar {{ text-align: right; margin-bottom: 1em; }}
.printbar button {{ background: var(--brand); color: #fff; border: none; padding: 0.5em 1.4em; border-radius: 5px; cursor: pointer; font-size: 0.9em; }}"#,
        brand = brand,
        font = font,
        paper = paper,
    )
}

/// Wrap already-rendered document body HTML in the full print page: doctype,
/// branded stylesheet, a print button, the body, and the shared footer.
pub fn render_doc_page(layout: &DocLayout, title: &str, inner_html: &str) -> String {
    let footer = if layout.footer_html.trim().is_empty() {
        String::new()
    } else {
        format!(r#"<div class="docfooter">{}</div>"#, layout.footer_html)
    };
    format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title>
<style>{css}</style></head>
<body>
<div class="printbar"><button onclick="window.print()">Print / Save as PDF</button></div>
{inner}
{footer}
</body></html>"#,
        title = html_escape(title),
        css = base_css(layout),
        inner = inner_html,
        footer = footer,
    )
}

/// End-to-end render for a plugin document: pick the custom template (or the
/// supplied built-in default), render it against the document's line records
/// and dotted globals, and wrap it in the branded print page.
///
/// `lines` are the iterable records (each a flat field map); `globals` are the
/// document header, company, party and totals as dotted keys. Both come from
/// the calling plugin's own query — this function does no document-specific SQL.
pub async fn render_document(
    db: &PgPool,
    doc_type: &str,
    default_template: &str,
    title: &str,
    globals: &BTreeMap<String, String>,
    lines: &[BTreeMap<String, String>],
) -> String {
    let layout = DocLayout::load(db).await;
    let body = match get_template(db, doc_type).await {
        Some(b) if !b.trim().is_empty() => b,
        _ => default_template.to_string(),
    };
    let rendered = crate::user_reports::render_template(&body, lines, globals);
    render_doc_page(&layout, title, &rendered)
}

/// Render an explicit template body against explicit data (no DB template
/// lookup) and wrap it in the branded page. Used by the editor's live preview
/// to render the *draft* body against a document type's sample data.
pub fn render_body(
    layout: &DocLayout,
    title: &str,
    body: &str,
    globals: &BTreeMap<String, String>,
    lines: &[BTreeMap<String, String>],
) -> String {
    let rendered = crate::user_reports::render_template(body, lines, globals);
    render_doc_page(layout, title, &rendered)
}

/// Allow only a small, safe CSS token (hex colour or simple keyword) to reach
/// the stylesheet, so a stored value can't break out of the `--brand` decl.
fn sanitize_css_token(v: &str, fallback: &str) -> String {
    let t = v.trim();
    let ok = !t.is_empty()
        && t.len() <= 32
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '#' || c == '(' || c == ')' || c == ',' || c == '%' || c == '.' || c == ' ');
    if ok { t.to_string() } else { fallback.to_string() }
}

/// Font family: strip anything that could terminate the CSS declaration.
fn sanitize_font(v: &str) -> String {
    let t: String = v
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | ',' | '-' | '\'' | '"'))
        .collect();
    let t = t.trim();
    if t.is_empty() { "Helvetica, Arial, sans-serif".to_string() } else { t.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_preserves_order_and_lookup() {
        let reg = PrintDocRegistry::new(vec![
            PrintDocType { doc_type: "a.x".into(), label: "X".into(), default_template: "t".into(), variables: vec![], sample_globals: BTreeMap::new(), sample_lines: vec![], default_config: None },
            PrintDocType { doc_type: "b.y".into(), label: "Y".into(), default_template: "u".into(), variables: vec![], sample_globals: BTreeMap::new(), sample_lines: vec![], default_config: None },
        ]);
        assert_eq!(reg.all().len(), 2);
        assert_eq!(reg.all()[0].doc_type, "a.x");
        assert_eq!(reg.get("b.y").unwrap().label, "Y");
        assert!(reg.get("missing").is_none());
    }

    #[test]
    fn css_rejects_injection_tokens() {
        // A malicious brand colour can't inject extra declarations.
        assert_eq!(sanitize_css_token("red; } body { display:none", "#000"), "#000");
        assert_eq!(sanitize_css_token("#ff0000", "#000"), "#ff0000");
        // Font sanitiser drops anything that could terminate the declaration
        // or open a tag — no ';', '<', '>', '/', '{', '}' survive.
        let f = sanitize_font("Arial; }</style><script>");
        assert!(!f.contains(['<', '>', ';', '/', '{', '}']));
        assert!(f.starts_with("Arial"));
    }

    #[test]
    fn build_template_honours_toggles_and_escapes_labels() {
        let mut cfg = LayoutConfig::transactional("Quotation");
        let full = build_template(&cfg);
        // Default renders every section + all six columns.
        assert!(full.contains("class=\"doc-title\">Quotation<"));
        assert!(full.contains("{{ line.code }}"));
        assert!(full.contains("{{ line.amount }}"));
        assert!(full.contains("class=\"buyer\""));
        assert!(full.contains("class=\"accept\""));

        // Turning sections off drops their markup.
        cfg.show_customer = false;
        cfg.show_signatures = false;
        cfg.columns[0].show = false; // hide the Code column
        let trimmed = build_template(&cfg);
        assert!(!trimmed.contains("class=\"buyer\""));
        assert!(!trimmed.contains("class=\"accept\""));
        assert!(!trimmed.contains("{{ line.code }}"));
        assert!(trimmed.contains("{{ line.description }}"));

        // A malicious label can neither inject markup nor a template directive.
        cfg.total_label = "</table><script>{{ x }}".into();
        let evil = build_template(&cfg);
        assert!(!evil.contains("<script>"));
        assert!(!evil.contains("{{ x }}"));
        assert!(evil.contains("&lt;script&gt;"));
    }

    #[test]
    fn base_css_embeds_brand() {
        let mut l = DocLayout::default();
        l.brand_color = "#123456".into();
        assert!(base_css(&l).contains("--brand: #123456"));
    }
}
