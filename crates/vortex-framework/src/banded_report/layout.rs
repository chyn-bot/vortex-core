//! Deterministic banded paginator.
//!
//! Because every band has a known height, page layout is pure arithmetic — no
//! browser measurement — so output is byte-for-byte repeatable and unit
//! testable. The walk performs classic control-break grouping and accumulates
//! report/page/group variables (`sum/count/avg/min/max`) as it places bands.
//!
//! Multi-column detail flow is supported for group-less reports (labels /
//! directories); when groups are present the layout is single-column so
//! full-width group headers/footers place cleanly.

use crate::banded_report::expr::{eval, EvalCtx};
use crate::banded_report::model::{Band, Element, ReportLayout, Variable};
use std::collections::BTreeMap;

/// One element positioned on a page in document units, with the evaluation
/// context captured at placement time (resolved to HTML in a second pass so
/// `pages()` can see the final page count).
#[derive(Debug, Clone)]
pub struct Placement {
    pub page: usize,
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    pub element: Element,
    /// Index into the dataset rows, if this placement is row-bound.
    pub row: Option<usize>,
    /// Variable snapshot visible to this element (`$V{name}`).
    pub vars: BTreeMap<String, f64>,
    pub row_num: u32,
}

/// Result of laying out a report.
#[derive(Debug, Clone)]
pub struct Laid {
    pub pages: usize,
    pub placements: Vec<Placement>,
    /// Page geometry echoed for the renderer (document units).
    pub page_w: f64,
    pub page_h: f64,
}

#[derive(Clone, Copy)]
enum Reset {
    Report,
    Page,
    Group(usize),
}

#[derive(Default, Clone)]
struct Acc {
    sum: f64,
    count: u64,
    min: Option<f64>,
    max: Option<f64>,
}

impl Acc {
    fn add(&mut self, v: f64) {
        self.sum += v;
        self.count += 1;
        self.min = Some(self.min.map_or(v, |m| m.min(v)));
        self.max = Some(self.max.map_or(v, |m| m.max(v)));
    }
    fn value(&self, calc: &str) -> f64 {
        match calc {
            "count" => self.count as f64,
            "avg" => {
                if self.count > 0 {
                    self.sum / self.count as f64
                } else {
                    0.0
                }
            }
            "min" => self.min.unwrap_or(0.0),
            "max" => self.max.unwrap_or(0.0),
            _ => self.sum, // sum
        }
    }
}

/// Lay out `layout` over `rows`. `params` feeds `$P{}` refs during expression
/// evaluation (group keys, print-when, variables).
pub fn lay_out(
    layout: &ReportLayout,
    rows: &[BTreeMap<String, String>],
    params: &BTreeMap<String, String>,
) -> Laid {
    let page = &layout.page;
    let bands = &layout.bands;
    let groups = &layout.dataset.groups;

    // Fixed vertical zones.
    let ph_h = band_h(&bands.page_header);
    let pf_h = band_h(&bands.page_footer);
    let ch_h = band_h(&bands.column_header);
    let base_content_top = page.margin.top + ph_h;
    let content_bottom = page.height - page.margin.bottom - pf_h;
    let content_left = page.margin.left;

    // Multi-column only without groups (see module docs).
    let cols: u32 = if groups.is_empty() { page.cols() } else { 1 };
    let col_w = if cols > 1 { page.column_width() } else { page.content_width() };
    let col_gap = page.column_gap;

    // Precompute group keys per row and each variable's reset scope.
    let group_keys = compute_group_keys(groups, rows, params);
    let resets: Vec<Reset> = layout.variables.iter().map(|v| resolve_reset(v, groups)).collect();

    let mut st = State {
        placements: Vec::new(),
        page: 0,
        col: 0,
        flow_y: 0.0,
        col_top: 0.0,
        accs: vec![Acc::default(); layout.variables.len()],
        row_num: 0,
        open_groups: Vec::new(),
    };

    // Geometry captured for closures.
    let geo = Geo {
        content_left,
        content_width: page.content_width(),
        base_content_top,
        content_bottom,
        col_w,
        col_gap,
        cols,
        ch_h,
    };

    // ── Open first page ──
    open_page(&mut st, layout, params, rows, &group_keys, &geo, true);

    // ── Row walk ──
    for i in 0..rows.len() {
        // 1. Control break: close footers for changed groups, open new headers.
        let break_from = if i == 0 {
            if groups.is_empty() {
                None
            } else {
                Some(0)
            }
        } else {
            (0..groups.len()).find(|&g| group_keys[i][g] != group_keys[i - 1][g])
        };

        if let Some(level) = break_from {
            if i > 0 {
                for g in (level..groups.len()).rev() {
                    // Footer of the just-closed group; representative row = i-1.
                    let key = &groups[g].footer;
                    if let Some(band) = bands.group_footers.get(key) {
                        let snap = snapshot(&layout.variables, &st.accs);
                        place_band(&mut st, layout, params, rows, &group_keys, &geo, band, Some(i - 1), true, &snap, 0);
                    }
                    reset_scope(&mut st, &resets, Reset::Group(g));
                    st.open_groups.retain(|(gi, _)| *gi != g);
                }
            }
            for g in level..groups.len() {
                reset_scope(&mut st, &resets, Reset::Group(g));
                let key = &groups[g].header;
                if let Some(band) = bands.group_headers.get(key) {
                    let snap = snapshot(&layout.variables, &st.accs);
                    place_band(&mut st, layout, params, rows, &group_keys, &geo, band, Some(i), true, &snap, 0);
                }
                st.open_groups.push((g, i));
            }
        }

        // 2. Accumulate variables with this row.
        accumulate(&mut st, layout, params, rows, &group_keys, i);

        // 3. Detail band (row-bound, column flow).
        st.row_num += 1;
        let snap = snapshot(&layout.variables, &st.accs);
        let rn = st.row_num;
        place_band(&mut st, layout, params, rows, &group_keys, &geo, &bands.detail, Some(i), false, &snap, rn);
    }

    // ── Close remaining groups (deepest first) ──
    if !rows.is_empty() {
        let last = rows.len() - 1;
        for g in (0..groups.len()).rev() {
            if st.open_groups.iter().any(|(gi, _)| *gi == g) {
                let key = &groups[g].footer;
                if let Some(band) = bands.group_footers.get(key) {
                    let snap = snapshot(&layout.variables, &st.accs);
                    place_band(&mut st, layout, params, rows, &group_keys, &geo, band, Some(last), true, &snap, 0);
                }
                reset_scope(&mut st, &resets, Reset::Group(g));
            }
        }
    }

    // ── Summary ──
    if band_h(&bands.summary) > 0.0 {
        // Full-width slot on a fresh column if we are mid-columns.
        if geo.cols > 1 && st.col > 0 {
            page_break(&mut st, layout, params, rows, &group_keys, &geo);
        }
        let last_row = if rows.is_empty() { None } else { Some(rows.len() - 1) };
        let snap = snapshot(&layout.variables, &st.accs);
        place_band(&mut st, layout, params, rows, &group_keys, &geo, &bands.summary, last_row, true, &snap, 0);
    }

    Laid { pages: st.page + 1, placements: st.placements, page_w: page.width, page_h: page.height }
}

struct Geo {
    content_left: f64,
    content_width: f64,
    base_content_top: f64,
    content_bottom: f64,
    col_w: f64,
    col_gap: f64,
    cols: u32,
    ch_h: f64,
}

struct State {
    placements: Vec<Placement>,
    page: usize,
    col: u32,
    flow_y: f64,
    col_top: f64,
    accs: Vec<Acc>,
    row_num: u32,
    /// (group index, representative first row) for currently open groups.
    open_groups: Vec<(usize, usize)>,
}

#[allow(clippy::too_many_arguments)]
fn open_page(
    st: &mut State,
    layout: &ReportLayout,
    params: &BTreeMap<String, String>,
    rows: &[BTreeMap<String, String>],
    group_keys: &[Vec<String>],
    geo: &Geo,
    first: bool,
) {
    let bands = &layout.bands;
    // Fixed-position page header / footer.
    if band_h(&bands.page_header) > 0.0 {
        emit_band_at(st, layout, params, rows, group_keys, geo, &bands.page_header, layout.page.margin.top, geo.content_left, geo.content_width, None, 0);
    }
    if band_h(&bands.page_footer) > 0.0 {
        let y = layout.page.height - layout.page.margin.bottom - band_h(&bands.page_footer);
        emit_band_at(st, layout, params, rows, group_keys, geo, &bands.page_footer, y, geo.content_left, geo.content_width, None, 0);
    }

    let mut y = geo.base_content_top;
    // Title: page 1 only, above the column header.
    if first && band_h(&bands.title) > 0.0 {
        emit_band_at(st, layout, params, rows, group_keys, geo, &bands.title, y, geo.content_left, geo.content_width, None, 0);
        y += band_h(&bands.title);
    }
    // Column header repeats on every page.
    if geo.ch_h > 0.0 {
        emit_band_at(st, layout, params, rows, group_keys, geo, &bands.column_header, y, geo.content_left, geo.content_width, None, 0);
        y += geo.ch_h;
    }
    // Reprint open group headers on continuation pages.
    if !first {
        let open = st.open_groups.clone();
        for (g, rep) in open {
            if layout.dataset.groups.get(g).map(|gr| gr.reprint).unwrap_or(false) {
                if let Some(band) = bands.group_headers.get(&layout.dataset.groups[g].header) {
                    let snap = snapshot(&layout.variables, &st.accs);
                    emit_band_ctx(st, layout, params, rows, group_keys, geo, band, y, geo.content_left, geo.content_width, Some(rep), &snap, 0);
                    y += band_h(band);
                }
            }
        }
    }

    st.col = 0;
    st.col_top = y;
    st.flow_y = y;
}

#[allow(clippy::too_many_arguments)]
fn page_break(
    st: &mut State,
    layout: &ReportLayout,
    params: &BTreeMap<String, String>,
    rows: &[BTreeMap<String, String>],
    group_keys: &[Vec<String>],
    geo: &Geo,
) {
    st.page += 1;
    // Page-scoped variables reset at each new page.
    let resets: Vec<Reset> = layout.variables.iter().map(|v| resolve_reset(v, &layout.dataset.groups)).collect();
    reset_scope(st, &resets, Reset::Page);
    open_page(st, layout, params, rows, group_keys, geo, false);
}

/// Place a flowing band (title/columnHeader excluded — those are page-fixed),
/// handling column advance and page breaks. `full_width` bands span the content
/// width; otherwise the band occupies the current detail column.
#[allow(clippy::too_many_arguments)]
fn place_band(
    st: &mut State,
    layout: &ReportLayout,
    params: &BTreeMap<String, String>,
    rows: &[BTreeMap<String, String>],
    group_keys: &[Vec<String>],
    geo: &Geo,
    band: &Band,
    row: Option<usize>,
    full_width: bool,
    vars: &BTreeMap<String, f64>,
    row_num: u32,
) {
    let h = band_h(band);
    if h <= 0.0 {
        return;
    }
    // Band-level print-when reserves no space when false.
    if let Some(cond) = &band.print_when {
        if !band_visible(cond, layout, params, rows, group_keys, row, vars) {
            return;
        }
    }

    // Fit check.
    if st.flow_y + h > geo.content_bottom + 0.01 {
        if !full_width && geo.cols > 1 && st.col + 1 < geo.cols {
            st.col += 1;
            st.flow_y = st.col_top;
        } else {
            page_break(st, layout, params, rows, group_keys, geo);
        }
    }

    let (x, w) = if full_width {
        (geo.content_left, geo.content_width)
    } else {
        (geo.content_left + st.col as f64 * (geo.col_w + geo.col_gap), geo.col_w)
    };
    let y = st.flow_y;
    emit_band_ctx(st, layout, params, rows, group_keys, geo, band, y, x, w, row, vars, row_num);
    st.flow_y += h;
}

/// Emit a band's elements at a fixed origin with a fresh variable snapshot.
#[allow(clippy::too_many_arguments)]
fn emit_band_at(
    st: &mut State,
    layout: &ReportLayout,
    params: &BTreeMap<String, String>,
    rows: &[BTreeMap<String, String>],
    group_keys: &[Vec<String>],
    geo: &Geo,
    band: &Band,
    y: f64,
    x: f64,
    w: f64,
    row: Option<usize>,
    row_num: u32,
) {
    let snap = snapshot(&layout.variables, &st.accs);
    emit_band_ctx(st, layout, params, rows, group_keys, geo, band, y, x, w, row, &snap, row_num);
}

#[allow(clippy::too_many_arguments)]
fn emit_band_ctx(
    st: &mut State,
    layout: &ReportLayout,
    params: &BTreeMap<String, String>,
    rows: &[BTreeMap<String, String>],
    group_keys: &[Vec<String>],
    geo: &Geo,
    band: &Band,
    y: f64,
    x: f64,
    _w: f64,
    row: Option<usize>,
    vars: &BTreeMap<String, f64>,
    row_num: u32,
) {
    let _ = geo;
    // Band-level print-when for fixed bands.
    if let Some(cond) = &band.print_when {
        if !band_visible(cond, layout, params, rows, group_keys, row, vars) {
            return;
        }
    }
    for el in &band.elements {
        st.placements.push(Placement {
            page: st.page,
            x: x + el.x,
            y: y + el.y,
            w: el.w,
            h: el.h,
            element: el.clone(),
            row,
            vars: vars.clone(),
            row_num,
        });
    }
}

// ─── Variables ───────────────────────────────────────────────────────────

fn accumulate(
    st: &mut State,
    layout: &ReportLayout,
    params: &BTreeMap<String, String>,
    rows: &[BTreeMap<String, String>],
    _group_keys: &[Vec<String>],
    i: usize,
) {
    let vars_snapshot = snapshot(&layout.variables, &st.accs);
    for (idx, var) in layout.variables.iter().enumerate() {
        let ctx = EvalCtx {
            row: &rows[i],
            params,
            vars: &vars_snapshot,
            page: (st.page + 1) as u32,
            pages: 0,
            row_num: st.row_num + 1,
        };
        let v = eval(&var.expr, &ctx).ok().and_then(|x| x.as_num()).unwrap_or(0.0);
        st.accs[idx].add(v);
    }
}

fn snapshot(vars: &[Variable], accs: &[Acc]) -> BTreeMap<String, f64> {
    vars.iter().zip(accs).map(|(v, a)| (v.name.clone(), a.value(&v.calc))).collect()
}

fn reset_scope(st: &mut State, resets: &[Reset], scope: Reset) {
    for (idx, r) in resets.iter().enumerate() {
        let hit = matches!(
            (r, scope),
            (Reset::Page, Reset::Page) | (Reset::Report, Reset::Report)
        ) || matches!((r, scope), (Reset::Group(a), Reset::Group(b)) if *a == b);
        if hit {
            st.accs[idx] = Acc::default();
        }
    }
}

fn resolve_reset(var: &Variable, groups: &[crate::banded_report::model::Group]) -> Reset {
    let r = var.reset.trim();
    if r == "report" || r.is_empty() {
        return Reset::Report;
    }
    if r == "page" {
        return Reset::Page;
    }
    if let Some(rest) = r.strip_prefix("group") {
        let rest = rest.trim_start_matches(':').trim();
        if rest.is_empty() {
            // Innermost group.
            return if groups.is_empty() { Reset::Report } else { Reset::Group(groups.len() - 1) };
        }
        // Match by header/footer band key, else parse as index.
        if let Some(idx) = groups.iter().position(|g| g.header == rest || g.footer == rest) {
            return Reset::Group(idx);
        }
        if let Ok(idx) = rest.parse::<usize>() {
            if idx < groups.len() {
                return Reset::Group(idx);
            }
        }
    }
    Reset::Report
}

// ─── Grouping / geometry helpers ─────────────────────────────────────────

fn compute_group_keys(
    groups: &[crate::banded_report::model::Group],
    rows: &[BTreeMap<String, String>],
    params: &BTreeMap<String, String>,
) -> Vec<Vec<String>> {
    let empty_vars = BTreeMap::new();
    rows.iter()
        .map(|row| {
            groups
                .iter()
                .map(|g| {
                    let ctx = EvalCtx { row, params, vars: &empty_vars, page: 1, pages: 1, row_num: 0 };
                    eval(&g.expr, &ctx).map(|v| v.to_display()).unwrap_or_default()
                })
                .collect()
        })
        .collect()
}

fn band_visible(
    cond: &str,
    _layout: &ReportLayout,
    params: &BTreeMap<String, String>,
    rows: &[BTreeMap<String, String>],
    _group_keys: &[Vec<String>],
    row: Option<usize>,
    vars: &BTreeMap<String, f64>,
) -> bool {
    let empty = BTreeMap::new();
    let r = row.and_then(|i| rows.get(i)).unwrap_or(&empty);
    let ctx = EvalCtx { row: r, params, vars, page: 1, pages: 1, row_num: 0 };
    eval(cond, &ctx).map(|v| v.truthy()).unwrap_or(true)
}

/// Effective band height: the declared height, or the extent of its elements
/// if the author left height at 0.
pub fn band_h(b: &Band) -> f64 {
    let ext = b.elements.iter().map(|e| e.y + e.h).fold(0.0, f64::max);
    b.height.max(ext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banded_report::model::*;

    fn rows(n: usize) -> Vec<BTreeMap<String, String>> {
        (0..n)
            .map(|i| {
                let mut m = BTreeMap::new();
                m.insert("id".to_string(), i.to_string());
                m.insert("amount".to_string(), "10".to_string());
                m.insert("grp".to_string(), if i < 3 { "A".to_string() } else { "B".to_string() });
                m
            })
            .collect()
    }

    fn detail_only_layout(detail_h: f64) -> ReportLayout {
        let mut l = ReportLayout::default();
        l.page.height = 200.0; // small page to force breaks
        l.page.margin = Margin { top: 10.0, right: 10.0, bottom: 10.0, left: 10.0 };
        l.bands.detail = Band {
            height: detail_h,
            elements: vec![Element { id: "d".into(), kind: "field".into(), expr: Some("$F{id}".into()), ..Default::default() }],
            print_when: None,
        };
        l
    }

    #[test]
    fn paginates_deterministically() {
        // content height = 200 - 10 - 10 = 180; detail 40 => 4 rows per page.
        let l = detail_only_layout(40.0);
        let laid = lay_out(&l, &rows(10), &BTreeMap::new());
        assert_eq!(laid.pages, 3); // 4 + 4 + 2
        assert_eq!(laid.placements.len(), 10);
        // First row on page 0 at content top (y=10).
        assert_eq!(laid.placements[0].page, 0);
        assert_eq!(laid.placements[0].y, 10.0);
        // Fifth row wraps to page 1.
        assert_eq!(laid.placements[4].page, 1);
    }

    #[test]
    fn group_footer_totals_reset_per_group() {
        let mut l = detail_only_layout(20.0);
        l.page.height = 1000.0; // one page
        l.dataset.groups = vec![Group { expr: "$F{grp}".into(), header: "gh".into(), footer: "gf".into(), reprint: false }];
        l.bands.group_headers.insert(
            "gh".into(),
            Band { height: 15.0, elements: vec![Element { id: "gh".into(), expr: Some("$F{grp}".into()), ..Default::default() }], print_when: None },
        );
        l.bands.group_footers.insert(
            "gf".into(),
            Band { height: 15.0, elements: vec![Element { id: "gf".into(), kind: "field".into(), expr: Some("$V{gtot}".into()), ..Default::default() }], print_when: None },
        );
        l.variables = vec![Variable { name: "gtot".into(), calc: "sum".into(), expr: "$F{amount}".into(), reset: "group:gf".into() }];

        let laid = lay_out(&l, &rows(5), &BTreeMap::new());
        // Two group footers: group A (3 rows * 10 = 30), group B (2 rows * 10 = 20).
        let footers: Vec<&Placement> = laid.placements.iter().filter(|p| p.element.id == "gf").collect();
        assert_eq!(footers.len(), 2);
        assert_eq!(*footers[0].vars.get("gtot").unwrap(), 30.0);
        assert_eq!(*footers[1].vars.get("gtot").unwrap(), 20.0);
    }

    #[test]
    fn report_summary_has_grand_total() {
        let mut l = detail_only_layout(20.0);
        l.page.height = 1000.0;
        l.bands.summary = Band {
            height: 20.0,
            elements: vec![Element { id: "sum".into(), kind: "field".into(), expr: Some("$V{grand}".into()), ..Default::default() }],
            print_when: None,
        };
        l.variables = vec![Variable { name: "grand".into(), calc: "sum".into(), expr: "$F{amount}".into(), reset: "report".into() }];
        let laid = lay_out(&l, &rows(5), &BTreeMap::new());
        let sum = laid.placements.iter().find(|p| p.element.id == "sum").unwrap();
        assert_eq!(*sum.vars.get("grand").unwrap(), 50.0);
    }

    #[test]
    fn multi_column_labels_flow_down_then_across() {
        let mut l = detail_only_layout(40.0);
        l.page.height = 200.0; // content 180 => 4 rows per column
        l.page.columns = 2;
        let laid = lay_out(&l, &rows(6), &BTreeMap::new());
        // 4 in column 0, 2 in column 1, all on page 0.
        assert!(laid.placements.iter().all(|p| p.page == 0));
        let col0_x = laid.placements[0].x;
        let col1_x = laid.placements[4].x;
        assert!(col1_x > col0_x); // 5th label moved to the right column
    }
}
