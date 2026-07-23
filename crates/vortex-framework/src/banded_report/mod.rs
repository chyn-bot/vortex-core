//! Report Studio — pixel-perfect banded report engine.
//!
//! A `banded` report (`ir_report.report_type = 'banded'`) pairs an
//! [`model::ReportLayout`] document (page geometry + bands + XY-positioned
//! elements + expressions/variables) with the shared `ir_report` authoring
//! surface (model, roles, filters, row limit). Rendering is deterministic:
//! [`layout::lay_out`] paginates by arithmetic and [`render::render_html`]
//! emits absolutely-positioned HTML that Chromium ([`crate::pdf`]) prints 1:1.
//!
//! Pipeline: [`load`] → [`render_to_html`] / [`render_to_pdf`].

pub mod datasource;
pub mod expr;
pub mod layout;
pub mod model;
pub mod render;

pub use model::ReportLayout;

use sqlx::{PgPool, Row};
use std::collections::BTreeMap;
use uuid::Uuid;

/// A loaded banded report: the `ir_report` metadata plus its layout document
/// and stored filters.
#[derive(Debug, Clone)]
pub struct BandedReport {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub model_name: String,
    pub required_role: Option<String>,
    pub row_limit: i32,
    pub layout: ReportLayout,
    /// Raw stored filters: (field, operator, value). Values may embed `$P{p}`.
    pub filters: Vec<(String, String, Option<String>)>,
}

impl BandedReport {
    /// Whether a user holding `roles` (or `is_admin`) may run this report.
    pub fn can_run(&self, roles: &[String], is_admin: bool) -> bool {
        match &self.required_role {
            None => true,
            Some(r) if r.is_empty() => true,
            Some(r) => is_admin || roles.iter().any(|x| x == r),
        }
    }
}

/// Load a banded report by `ir_report.id`. Returns `Ok(None)` when the row is
/// absent or not a banded report.
pub async fn load(db: &PgPool, id: Uuid) -> Result<Option<BandedReport>, String> {
    let row = sqlx::query(
        "SELECT id, code, name, model_name, report_type, required_role, row_limit \
         FROM ir_report WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?;
    let Some(row) = row else { return Ok(None) };
    let rtype: String = row.get("report_type");
    if rtype != "banded" {
        return Ok(None);
    }

    let doc_json: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT document FROM ir_report_layout WHERE report_id = $1")
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(|e| e.to_string())?;
    let layout: ReportLayout = match doc_json {
        Some(v) => serde_json::from_value(v).map_err(|e| format!("bad layout document: {e}"))?,
        None => ReportLayout::default(),
    };

    let frows = sqlx::query("SELECT field, operator, value FROM ir_report_filter WHERE report_id = $1 ORDER BY sequence")
        .bind(id)
        .fetch_all(db)
        .await
        .map_err(|e| e.to_string())?;
    let filters = frows
        .iter()
        .map(|r| (r.get::<String, _>("field"), r.get::<String, _>("operator"), r.try_get::<Option<String>, _>("value").ok().flatten()))
        .collect();

    Ok(Some(BandedReport {
        id: row.get("id"),
        code: row.get("code"),
        name: row.get("name"),
        model_name: row.get("model_name"),
        required_role: row.try_get("required_role").ok().flatten(),
        row_limit: row.get("row_limit"),
        layout,
        filters,
    }))
}

/// Persist a layout document, upserting `ir_report_layout` and bumping version.
pub async fn save_document(db: &PgPool, report_id: Uuid, doc: &ReportLayout, user: Option<Uuid>) -> Result<(), String> {
    let value = serde_json::to_value(doc).map_err(|e| e.to_string())?;
    sqlx::query(
        "INSERT INTO ir_report_layout (report_id, document, version, updated_at, updated_by) \
         VALUES ($1, $2, 1, now(), $3) \
         ON CONFLICT (report_id) DO UPDATE SET document = EXCLUDED.document, \
            version = ir_report_layout.version + 1, updated_at = now(), updated_by = EXCLUDED.updated_by",
    )
    .bind(report_id)
    .bind(value)
    .bind(user)
    .execute(db)
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Resolve the effective parameter map: layout-declared defaults overridden by
/// caller-supplied `provided` (typically query-string values).
pub fn resolve_params(layout: &ReportLayout, provided: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for p in &layout.params {
        let v = provided.get(&p.name).cloned().or_else(|| p.default.clone()).unwrap_or_default();
        out.insert(p.name.clone(), v);
    }
    // Also pass through any provided keys not declared (forgiving).
    for (k, v) in provided {
        out.entry(k.clone()).or_insert_with(|| v.clone());
    }
    out
}

/// Substitute `$P{name}` tokens inside a stored filter value with the resolved
/// param value. A value that is exactly `$P{name}` yields the raw param.
fn resolve_filter_value(raw: Option<&str>, params: &BTreeMap<String, String>) -> Option<String> {
    let raw = raw?;
    let mut s = raw.to_string();
    for (k, v) in params {
        s = s.replace(&format!("$P{{{k}}}"), v);
    }
    // Blank any placeholder referencing a param that was never provided, so an
    // unfilled optional parameter drops its filter rather than matching the
    // literal token `$P{name}`.
    while let Some(start) = s.find("$P{") {
        match s[start..].find('}') {
            Some(rel) => s.replace_range(start..start + rel + 1, ""),
            None => break,
        }
    }
    Some(s)
}

/// Build the datasource filter list from stored filters + resolved params.
/// A filter whose value resolves to empty and referenced an undefined param is
/// dropped so an unfilled optional parameter widens rather than empties results.
fn build_filters(report: &BandedReport, params: &BTreeMap<String, String>) -> Vec<datasource::Filter> {
    report
        .filters
        .iter()
        .filter_map(|(field, op, value)| {
            let had_placeholder = value.as_deref().map(|v| v.contains("$P{")).unwrap_or(false);
            let resolved = resolve_filter_value(value.as_deref(), params);
            if had_placeholder && resolved.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
                return None; // optional param left blank → skip this filter
            }
            Some(datasource::Filter { field: field.clone(), operator: op.clone(), value: resolved })
        })
        .collect()
}

/// Load a banded report by `ir_report.code`.
pub async fn load_by_code(db: &PgPool, code: &str) -> Result<Option<BandedReport>, String> {
    let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM ir_report WHERE code = $1")
        .bind(code)
        .fetch_optional(db)
        .await
        .map_err(|e| e.to_string())?;
    match id {
        Some(id) => load(db, id).await,
        None => Ok(None),
    }
}

/// Render a loaded report to standalone HTML, inlining any subreports.
pub async fn render_to_html(db: &PgPool, report: &BandedReport, provided: &BTreeMap<String, String>) -> Result<String, String> {
    let params = resolve_params(&report.layout, provided);
    let filters = build_filters(report, &params);
    let rows = datasource::fetch(db, &report.model_name, &report.layout.dataset, &filters, report.row_limit).await?;
    let laid = layout::lay_out(&report.layout, &rows, &params);

    // Subreport prepass: for each subreport placement, fetch the child report's
    // data (parameterized from the parent row) and render a contained fragment.
    // Nested subreports render one level deep — the fragment path passes no
    // further subreports, which also bounds recursion.
    let mut subs = render::SubMap::new();
    let mut child_cache: BTreeMap<String, Option<BandedReport>> = BTreeMap::new();
    for p in &laid.placements {
        if p.element.kind != "subreport" {
            continue;
        }
        let (Some(sub), Some(rowi)) = (p.element.subreport.as_ref(), p.row) else { continue };
        if !child_cache.contains_key(&sub.code) {
            let loaded = load_by_code(db, &sub.code).await?;
            child_cache.insert(sub.code.clone(), loaded);
        }
        let Some(Some(child)) = child_cache.get(&sub.code).cloned() else { continue };

        let empty_vars = BTreeMap::new();
        let parent_row = rows.get(rowi).cloned().unwrap_or_default();
        let mut child_provided = BTreeMap::new();
        for (cparam, pexpr) in &sub.param_map {
            let ctx = expr::EvalCtx { row: &parent_row, params: &params, vars: &empty_vars, page: 1, pages: 1, row_num: 0 };
            let val = expr::eval(pexpr, &ctx).map(|v| v.to_display()).unwrap_or_default();
            child_provided.insert(cparam.clone(), val);
        }
        let cparams = resolve_params(&child.layout, &child_provided);
        let cfilters = build_filters(&child, &cparams);
        let crows = datasource::fetch(db, &child.model_name, &child.layout.dataset, &cfilters, child.row_limit).await?;
        let frag = render::render_child_fragment(&child.layout, &crows, &cparams, p.w);
        subs.insert((p.element.id.clone(), rowi), frag);
    }

    Ok(render::render_html_ex(&report.layout, &laid, &rows, &params, &subs))
}

/// Pure render from an in-memory layout + rows (used by preview and tests).
pub fn render_layout_html(layout: &ReportLayout, rows: &[BTreeMap<String, String>], params: &BTreeMap<String, String>) -> String {
    let laid = layout::lay_out(layout, rows, params);
    render::render_html(layout, &laid, rows, params)
}

/// Render a loaded report to PDF bytes via the Chromium engine. The exact page
/// geometry is passed through so the print is 1:1 with the layout.
pub async fn render_to_pdf(db: &PgPool, report: &BandedReport, provided: &BTreeMap<String, String>) -> Result<Vec<u8>, String> {
    let html = render_to_html(db, report, provided).await?;
    let opts = pdf_options_for(&report.layout);
    crate::pdf::html_to_pdf(&html, &opts).await.map_err(|e| e.to_string())
}

/// Build [`crate::pdf::PdfOptions`] that force the layout's exact page size.
pub fn pdf_options_for(layout: &ReportLayout) -> crate::pdf::PdfOptions {
    let w_in = layout.to_inches(layout.page.width);
    let h_in = layout.to_inches(layout.page.height);
    crate::pdf::PdfOptions {
        landscape: false,
        paper: crate::pdf::Paper::A4,
        print_background: true,
        margin_in: 0.0,
        exact_in: Some((w_in, h_in)),
    }
}

/// Structural validation of a layout document. Returns human-readable issues;
/// empty means valid enough to render.
pub fn validate(layout: &ReportLayout) -> Vec<String> {
    let mut issues = Vec::new();
    if !matches!(layout.unit.as_str(), "pt" | "mm" | "px") {
        issues.push(format!("unknown unit '{}'", layout.unit));
    }
    if layout.page.width <= 0.0 || layout.page.height <= 0.0 {
        issues.push("page width/height must be positive".into());
    }
    // Group header/footer keys must reference an existing band.
    for (i, g) in layout.dataset.groups.iter().enumerate() {
        if !g.header.is_empty() && !layout.bands.group_headers.contains_key(&g.header) {
            issues.push(format!("group {i}: header band '{}' not defined", g.header));
        }
        if !g.footer.is_empty() && !layout.bands.group_footers.contains_key(&g.footer) {
            issues.push(format!("group {i}: footer band '{}' not defined", g.footer));
        }
    }
    // Duplicate element ids across the doc.
    let mut seen = std::collections::HashSet::new();
    for e in all_elements(layout) {
        if !e.id.is_empty() && !seen.insert(e.id.clone()) {
            issues.push(format!("duplicate element id '{}'", e.id));
        }
    }
    issues
}

/// Starter templates authors can scaffold from (Crystal/Jasper ship these too).
/// Each uses generic field names the author adapts to their model. Returns the
/// layout as a `serde_json::Value` so it round-trips through the same path the
/// designer saves. `title` personalises headings.
pub fn sample_layout(name: &str, title: &str) -> Option<serde_json::Value> {
    let v = match name {
        "invoice" => serde_json::json!({
            "unit":"pt",
            "page":{"size":"A4","orientation":"portrait","width":595.0,"height":842.0,
                    "margin":{"top":40.0,"right":40.0,"bottom":40.0,"left":40.0}},
            "dataset":{"sort":[{"field":"id","dir":"asc"}]},
            "variables":[{"name":"total","calc":"sum","expr":"$F{amount}","reset":"report"}],
            "bands":{
                "title":{"height":90.0,"elements":[
                    {"id":"h_title","type":"staticText","x":0.0,"y":0.0,"w":300.0,"h":26.0,"text":title,"style":{"size":22.0,"bold":true}},
                    {"id":"h_partner","type":"field","x":0.0,"y":34.0,"w":300.0,"h":16.0,"expr":"$F{partner}","style":{"size":11.0}},
                    {"id":"h_date","type":"field","x":355.0,"y":34.0,"w":160.0,"h":16.0,"expr":"\"Date: \" + $F{date}","style":{"align":"right"}}]},
                "columnHeader":{"height":22.0,"elements":[
                    {"id":"ch_desc","type":"staticText","x":0.0,"y":4.0,"w":280.0,"h":14.0,"text":"Description","style":{"bold":true}},
                    {"id":"ch_qty","type":"staticText","x":290.0,"y":4.0,"w":60.0,"h":14.0,"text":"Qty","style":{"bold":true,"align":"right"}},
                    {"id":"ch_price","type":"staticText","x":355.0,"y":4.0,"w":70.0,"h":14.0,"text":"Price","style":{"bold":true,"align":"right"}},
                    {"id":"ch_amt","type":"staticText","x":430.0,"y":4.0,"w":85.0,"h":14.0,"text":"Amount","style":{"bold":true,"align":"right"}},
                    {"id":"ch_rule","type":"line","x":0.0,"y":20.0,"w":515.0,"h":1.0,"style":{"border":{"color":"#333333"}}}]},
                "detail":{"height":18.0,"elements":[
                    {"id":"d_desc","type":"field","x":0.0,"y":2.0,"w":280.0,"h":14.0,"expr":"$F{name}"},
                    {"id":"d_qty","type":"field","x":290.0,"y":2.0,"w":60.0,"h":14.0,"expr":"$F{quantity}","style":{"align":"right"}},
                    {"id":"d_price","type":"field","x":355.0,"y":2.0,"w":70.0,"h":14.0,"expr":"$F{price}","style":{"align":"right","format":"#,##0.00"}},
                    {"id":"d_amt","type":"field","x":430.0,"y":2.0,"w":85.0,"h":14.0,"expr":"$F{amount}","style":{"align":"right","format":"#,##0.00"}}]},
                "summary":{"height":40.0,"elements":[
                    {"id":"s_rule","type":"line","x":290.0,"y":2.0,"w":225.0,"h":1.0,"style":{"border":{"color":"#333333"}}},
                    {"id":"s_lbl","type":"staticText","x":290.0,"y":10.0,"w":130.0,"h":16.0,"text":"Total","style":{"bold":true,"align":"right"}},
                    {"id":"s_total","type":"field","x":430.0,"y":10.0,"w":85.0,"h":16.0,"expr":"$V{total}","style":{"bold":true,"align":"right","format":"#,##0.00"}}]},
                "pageFooter":{"height":22.0,"elements":[
                    {"id":"pf","type":"field","x":0.0,"y":6.0,"w":515.0,"h":12.0,"expr":"\"Page \" + page() + \" of \" + pages()","style":{"align":"right","size":8.0,"color":"#888888"}}]}
            }
        }),
        "statement" => serde_json::json!({
            "unit":"pt",
            "page":{"size":"A4","orientation":"portrait","width":595.0,"height":842.0,
                    "margin":{"top":40.0,"right":40.0,"bottom":40.0,"left":40.0}},
            "dataset":{"sort":[{"field":"date","dir":"asc"}],
                       "groups":[{"expr":"$F{partner}","header":"g0h","footer":"g0f","reprint":true}]},
            "variables":[{"name":"bal","calc":"sum","expr":"$F{amount}","reset":"group"}],
            "bands":{
                "title":{"height":40.0,"elements":[
                    {"id":"h","type":"staticText","x":0.0,"y":6.0,"w":515.0,"h":26.0,"text":title,"style":{"size":20.0,"bold":true}}]},
                "groupHeaders":{"g0h":{"height":22.0,"elements":[
                    {"id":"gh","type":"field","x":0.0,"y":4.0,"w":400.0,"h":16.0,"expr":"$F{partner}","style":{"bold":true,"size":12.0}}]}},
                "columnHeader":{"height":18.0,"elements":[
                    {"id":"ch_d","type":"staticText","x":0.0,"y":2.0,"w":120.0,"h":14.0,"text":"Date","style":{"bold":true}},
                    {"id":"ch_r","type":"staticText","x":130.0,"y":2.0,"w":270.0,"h":14.0,"text":"Reference","style":{"bold":true}},
                    {"id":"ch_a","type":"staticText","x":410.0,"y":2.0,"w":105.0,"h":14.0,"text":"Amount","style":{"bold":true,"align":"right"}}]},
                "detail":{"height":16.0,"elements":[
                    {"id":"d_d","type":"field","x":0.0,"y":1.0,"w":120.0,"h":14.0,"expr":"$F{date}","style":{"format":"dd/MM/yyyy"}},
                    {"id":"d_r","type":"field","x":130.0,"y":1.0,"w":270.0,"h":14.0,"expr":"$F{name}"},
                    {"id":"d_a","type":"field","x":410.0,"y":1.0,"w":105.0,"h":14.0,"expr":"$F{amount}","style":{"align":"right","format":"#,##0.00"}}]},
                "groupFooters":{"g0f":{"height":22.0,"elements":[
                    {"id":"gf_l","type":"staticText","x":250.0,"y":4.0,"w":150.0,"h":14.0,"text":"Balance","style":{"bold":true,"align":"right"}},
                    {"id":"gf_v","type":"field","x":410.0,"y":4.0,"w":105.0,"h":14.0,"expr":"$V{bal}","style":{"bold":true,"align":"right","format":"#,##0.00"}}]}},
                "pageFooter":{"height":20.0,"elements":[
                    {"id":"pf","type":"field","x":0.0,"y":4.0,"w":515.0,"h":12.0,"expr":"\"Page \" + page() + \" of \" + pages()","style":{"align":"right","size":8.0,"color":"#888888"}}]}
            }
        }),
        "labels" => serde_json::json!({
            "unit":"mm",
            "page":{"size":"A4","orientation":"portrait","width":210.0,"height":297.0,
                    "margin":{"top":15.0,"right":8.0,"bottom":15.0,"left":8.0},
                    "columns":3,"columnGap":3.0},
            "bands":{
                "detail":{"height":32.0,"elements":[
                    {"id":"l_name","type":"field","x":2.0,"y":2.0,"w":58.0,"h":6.0,"expr":"$F{name}","style":{"bold":true,"size":9.0}},
                    {"id":"l_addr","type":"field","x":2.0,"y":9.0,"w":58.0,"h":18.0,"expr":"$F{address}","style":{"size":8.0}}]}
            }
        }),
        _ => return None,
    };
    Some(v)
}

fn all_elements(layout: &ReportLayout) -> impl Iterator<Item = &model::Element> {
    let b = &layout.bands;
    let fixed = [&b.title, &b.page_header, &b.column_header, &b.detail, &b.column_footer, &b.page_footer, &b.summary];
    fixed
        .into_iter()
        .chain(b.group_headers.values())
        .chain(b.group_footers.values())
        .flat_map(|band| band.elements.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banded_report::model::*;

    #[test]
    fn resolve_params_applies_defaults_and_overrides() {
        let mut l = ReportLayout::default();
        l.params = vec![
            Param { name: "state".into(), kind: "text".into(), label: "State".into(), default: Some("open".into()) },
            Param { name: "year".into(), kind: "number".into(), label: "Year".into(), default: None },
        ];
        let mut provided = BTreeMap::new();
        provided.insert("year".to_string(), "2026".to_string());
        let p = resolve_params(&l, &provided);
        assert_eq!(p.get("state").unwrap(), "open"); // default
        assert_eq!(p.get("year").unwrap(), "2026"); // override
    }

    #[test]
    fn filter_placeholder_substitution() {
        let mut params = BTreeMap::new();
        params.insert("st".to_string(), "posted".to_string());
        assert_eq!(resolve_filter_value(Some("$P{st}"), &params).as_deref(), Some("posted"));
        assert_eq!(resolve_filter_value(Some("prefix-$P{st}"), &params).as_deref(), Some("prefix-posted"));
    }

    #[test]
    fn blank_optional_param_drops_filter() {
        let report = BandedReport {
            id: Uuid::nil(),
            code: "c".into(),
            name: "n".into(),
            model_name: "m".into(),
            required_role: None,
            row_limit: 100,
            layout: ReportLayout::default(),
            filters: vec![("state".into(), "=".into(), Some("$P{state}".into()))],
        };
        let params = BTreeMap::new(); // state not provided
        assert!(build_filters(&report, &params).is_empty());
    }

    #[test]
    fn validate_flags_missing_group_band() {
        let mut l = ReportLayout::default();
        l.dataset.groups = vec![Group { expr: "$F{x}".into(), header: "missing".into(), footer: String::new(), reprint: false }];
        let issues = validate(&l);
        assert!(issues.iter().any(|s| s.contains("header band 'missing'")));
    }

    #[test]
    fn sample_templates_parse_and_validate() {
        for name in ["invoice", "statement", "labels"] {
            let v = sample_layout(name, "Demo").unwrap_or_else(|| panic!("missing sample {name}"));
            let layout: ReportLayout = serde_json::from_value(v).unwrap_or_else(|e| panic!("{name} parse: {e}"));
            let issues = validate(&layout);
            assert!(issues.is_empty(), "{name} invalid: {issues:?}");
        }
        assert!(sample_layout("nope", "x").is_none());
    }

    #[test]
    fn statement_sample_renders_group_totals() {
        // The statement template groups by partner and sums a group balance.
        let v = sample_layout("statement", "Statement").unwrap();
        let layout: ReportLayout = serde_json::from_value(v).unwrap();
        let rows: Vec<BTreeMap<String, String>> = [("Acme", "100"), ("Acme", "50"), ("Beta", "25")]
            .iter()
            .map(|(p, a)| {
                let mut m = BTreeMap::new();
                m.insert("partner".to_string(), p.to_string());
                m.insert("amount".to_string(), a.to_string());
                m.insert("name".to_string(), "inv".to_string());
                m.insert("date".to_string(), "2026-07-19".to_string());
                m
            })
            .collect();
        let html = render_layout_html(&layout, &rows, &BTreeMap::new());
        assert!(html.contains("150.00")); // Acme balance
        assert!(html.contains("25.00")); // Beta balance
    }

    #[test]
    fn can_run_respects_required_role() {
        let mut report = BandedReport {
            id: Uuid::nil(),
            code: "c".into(),
            name: "n".into(),
            model_name: "m".into(),
            required_role: Some("Finance".into()),
            row_limit: 1,
            layout: ReportLayout::default(),
            filters: vec![],
        };
        assert!(!report.can_run(&["Sales".into()], false));
        assert!(report.can_run(&["Finance".into()], false));
        assert!(report.can_run(&[], true)); // admin
        report.required_role = None;
        assert!(report.can_run(&[], false));
    }
}
