//! Pixel-perfect HTML emitter for a laid-out banded report.
//!
//! Each page is a `position:relative` box sized to the exact page geometry;
//! every element is an absolutely-positioned child in document units. The
//! `@page` rule matches the page box so Chromium (via [`crate::pdf`]) prints
//! 1:1. All dataset values are HTML-escaped; image sources are scheme-checked.

use crate::banded_report::expr::{eval_display, EvalCtx};
use crate::banded_report::layout::Laid;
use crate::banded_report::model::{Element, ReportLayout};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Pre-rendered subreport fragments keyed by `(element id, detail row index)`.
/// The orchestrator ([`super::render_to_html`]) fills this by fetching each
/// child report's data per row; the pure render path passes it empty.
pub type SubMap = BTreeMap<(String, usize), String>;

/// Render the full standalone HTML document for `laid` (no subreports).
pub fn render_html(
    layout: &ReportLayout,
    laid: &Laid,
    rows: &[BTreeMap<String, String>],
    params: &BTreeMap<String, String>,
) -> String {
    render_html_ex(layout, laid, rows, params, &SubMap::new())
}

/// Render with pre-resolved subreport fragments.
pub fn render_html_ex(
    layout: &ReportLayout,
    laid: &Laid,
    rows: &[BTreeMap<String, String>],
    params: &BTreeMap<String, String>,
    subs: &SubMap,
) -> String {
    let u = layout.css_unit();
    let pw = laid.page_w;
    let ph = laid.page_h;

    let mut style = String::new();
    let _ = write!(
        style,
        "@page{{size:{pw}{u} {ph}{u};margin:0}}\
         *{{margin:0;padding:0;box-sizing:border-box}}\
         html,body{{background:#f4f4f5}}\
         .rp-page{{position:relative;width:{pw}{u};height:{ph}{u};background:#fff;overflow:hidden;\
           page-break-after:always;break-after:page}}\
         .rp-page:last-child{{page-break-after:auto;break-after:auto}}\
         .rp-el{{position:absolute;overflow:hidden;display:flex;line-height:1.15}}\
         @media screen{{body{{padding:16px}}.rp-page{{margin:0 auto 16px;box-shadow:0 1px 6px rgba(0,0,0,.18)}}}}"
    );

    // Group placements by page (they are emitted in flow order already).
    let mut pages: Vec<String> = vec![String::new(); laid.pages.max(1)];
    for p in &laid.placements {
        let el_html = render_element(layout, p, rows, params, laid.pages as u32, subs);
        if let Some(buf) = pages.get_mut(p.page) {
            buf.push_str(&el_html);
        }
    }

    let mut body = String::new();
    for page in &pages {
        let _ = write!(body, "<div class=\"rp-page\">{page}</div>");
    }

    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><style>{style}</style></head><body>{body}</body></html>"
    )
}

fn render_element(
    layout: &ReportLayout,
    p: &crate::banded_report::layout::Placement,
    rows: &[BTreeMap<String, String>],
    params: &BTreeMap<String, String>,
    total_pages: u32,
    subs: &SubMap,
) -> String {
    let el = &p.element;
    let empty = BTreeMap::new();
    let row = p.row.and_then(|i| rows.get(i)).unwrap_or(&empty);
    let ctx = EvalCtx {
        row,
        params,
        vars: &p.vars,
        page: (p.page + 1) as u32,
        pages: total_pages,
        row_num: p.row_num,
    };

    // Per-element visibility.
    if let Some(cond) = &el.print_when {
        let visible = crate::banded_report::expr::eval(cond, &ctx).map(|v| v.truthy()).unwrap_or(true);
        if !visible {
            return String::new();
        }
    }

    let u = layout.css_unit();
    let pos = format!("left:{}{u};top:{}{u};width:{}{u};height:{}{u}", p.x, p.y, p.w, p.h);

    match el.kind.as_str() {
        "line" => render_line(el, &pos, u),
        "box" => render_box(el, &pos),
        "image" => render_image(el, &ctx, &pos),
        "barcode" => render_barcode(el, &ctx, &pos),
        "subreport" => render_subreport(el, p, &pos, subs),
        _ => render_text(el, &ctx, &pos), // field | staticText
    }
}

fn render_text(el: &Element, ctx: &EvalCtx, pos: &str) -> String {
    let s = &el.style;
    let value = if el.kind == "staticText" {
        el.text.clone().unwrap_or_default()
    } else {
        eval_display(el.expr.as_deref().unwrap_or(""), ctx, s.format.as_deref())
    };
    let mut css = format!(
        "{pos};color:{};font-family:{};font-size:{}pt;{}text-align:{};{}{}{}",
        esc_attr(&s.color),
        esc_attr(&s.font),
        s.size,
        justify(&s.align),
        esc_attr(&s.align),
        align_items(&s.valign),
        if s.bold { "font-weight:700;" } else { "" },
        if s.italic { "font-style:italic;" } else { "" },
    );
    if s.underline {
        css.push_str("text-decoration:underline;");
    }
    if let Some(bg) = &s.bg {
        let _ = write!(css, "background:{};", esc_attr(bg));
    }
    if !s.wrap {
        css.push_str("white-space:nowrap;");
    }
    css.push_str(&border_css(&s.border));
    // Inner span keeps text within the flex box and lets ellipsis clip.
    format!("<div class=\"rp-el\" style=\"{css}\"><span style=\"width:100%\">{}</span></div>", esc(&value))
}

fn render_box(el: &Element, pos: &str) -> String {
    let s = &el.style;
    let mut css = format!("{pos};");
    if let Some(bg) = &s.bg {
        let _ = write!(css, "background:{};", esc_attr(bg));
    }
    // A box with no explicit border still gets a hairline so it's visible.
    let b = &s.border;
    if b.top == 0.0 && b.right == 0.0 && b.bottom == 0.0 && b.left == 0.0 {
        let _ = write!(css, "border:1px solid {};", esc_attr(&b.color));
    } else {
        css.push_str(&border_css(b));
    }
    format!("<div class=\"rp-el\" style=\"{css}\"></div>")
}

fn render_line(el: &Element, pos: &str, _u: &str) -> String {
    let color = esc_attr(&el.style.border.color);
    // Orientation from the box aspect: wide => horizontal rule, tall => vertical.
    let css = if el.w >= el.h {
        format!("{pos};border-top:{}px solid {}", el.style.border.top.max(1.0), color)
    } else {
        format!("{pos};border-left:{}px solid {}", el.style.border.left.max(1.0), color)
    };
    format!("<div class=\"rp-el\" style=\"{css}\"></div>")
}

fn render_image(el: &Element, ctx: &EvalCtx, pos: &str) -> String {
    let src = eval_display(el.expr.as_deref().unwrap_or(""), ctx, None);
    if !safe_img_src(&src) {
        return String::new();
    }
    format!(
        "<div class=\"rp-el\" style=\"{pos};align-items:center;justify-content:center\">\
         <img src=\"{}\" style=\"max-width:100%;max-height:100%;object-fit:contain\"/></div>",
        esc_attr(&src)
    )
}

fn render_barcode(el: &Element, ctx: &EvalCtx, pos: &str) -> String {
    let value = eval_display(el.expr.as_deref().unwrap_or(""), ctx, None);
    if value.is_empty() {
        return String::new();
    }
    let sym = el.barcode.as_ref().map(|b| b.symbology.as_str()).unwrap_or("qr");
    let svg = match sym {
        "code128" => barcode_1d_svg(&value, "code128"),
        "ean13" => barcode_1d_svg(&value, "ean13"),
        _ => crate::qr::qr_svg(&value, 120),
    };
    match svg {
        Some(svg) => format!(
            "<div class=\"rp-el\" style=\"{pos};align-items:center;justify-content:center\">\
             <div style=\"width:100%;height:100%\">{svg}</div></div>",
            svg = inline_svg_fit(&svg)
        ),
        None => String::new(),
    }
}

fn render_subreport(el: &Element, p: &crate::banded_report::layout::Placement, pos: &str, subs: &SubMap) -> String {
    let key = (el.id.clone(), p.row.unwrap_or(usize::MAX));
    match subs.get(&key) {
        Some(inner) => format!("<div class=\"rp-el\" style=\"{pos};display:block\">{inner}</div>"),
        None => String::new(),
    }
}

/// Render a child banded report as a self-contained relative-positioned block
/// (no page chrome), sized to `box_w` document units and flowing on a single
/// tall page. Used to inline subreports inside a parent element's box.
pub fn render_child_fragment(
    child: &ReportLayout,
    rows: &[BTreeMap<String, String>],
    params: &BTreeMap<String, String>,
    box_w: f64,
) -> String {
    let mut l = child.clone();
    l.page.width = box_w + l.page.margin.left + l.page.margin.right;
    l.page.height = 1_000_000.0; // single tall page: no breaks inside a box
    l.page.columns = 1;
    l.page.margin.top = 0.0;
    l.page.margin.bottom = 0.0;
    let laid = crate::banded_report::layout::lay_out(&l, rows, params);
    let empty = SubMap::new();
    let mut body = String::new();
    for p in &laid.placements {
        body.push_str(&render_element(&l, p, rows, params, 1, &empty));
    }
    let used = laid.placements.iter().map(|p| p.y + p.h).fold(0.0, f64::max);
    let u = l.css_unit();
    format!("<div style=\"position:relative;width:{box_w}{u};height:{used}{u}\">{body}</div>")
}

/// Render a 1D barcode as SVG via `barcoders`.
fn barcode_1d_svg(value: &str, sym: &str) -> Option<String> {
    use barcoders::generators::svg::SVG;
    let encoded = match sym {
        "ean13" => {
            use barcoders::sym::ean13::EAN13;
            EAN13::new(value).ok()?.encode()
        }
        _ => {
            use barcoders::sym::code128::Code128;
            // Code128 requires a leading charset selector; default to Code B.
            let input = if value.starts_with('\u{0181}') || value.starts_with('\u{0180}') || value.starts_with('\u{0182}') {
                value.to_string()
            } else {
                format!("\u{0181}{value}") // Ɓ = start Code B
            };
            Code128::new(input).ok()?.encode()
        }
    };
    let svg = SVG::new(80).generate(&encoded).ok()?;
    Some(svg)
}

fn inline_svg_fit(svg: &str) -> String {
    // Let the SVG scale to its container.
    if svg.contains("<svg") && !svg.contains("width=\"100%\"") {
        svg.replacen("<svg", "<svg preserveAspectRatio=\"xMidYMid meet\" style=\"width:100%;height:100%\"", 1)
    } else {
        svg.to_string()
    }
}

// ─── CSS helpers ─────────────────────────────────────────────────────────

fn justify(align: &str) -> &'static str {
    match align {
        "center" => "justify-content:center;",
        "right" => "justify-content:flex-end;",
        "justify" => "justify-content:stretch;",
        _ => "justify-content:flex-start;",
    }
}

fn align_items(valign: &str) -> &'static str {
    match valign {
        "top" => "align-items:flex-start;",
        "bottom" => "align-items:flex-end;",
        _ => "align-items:center;",
    }
}

fn border_css(b: &crate::banded_report::model::Border) -> String {
    let mut s = String::new();
    let c = esc_attr(&b.color);
    if b.top > 0.0 {
        let _ = write!(s, "border-top:{}px solid {};", b.top, c);
    }
    if b.right > 0.0 {
        let _ = write!(s, "border-right:{}px solid {};", b.right, c);
    }
    if b.bottom > 0.0 {
        let _ = write!(s, "border-bottom:{}px solid {};", b.bottom, c);
    }
    if b.left > 0.0 {
        let _ = write!(s, "border-left:{}px solid {};", b.left, c);
    }
    s
}

fn safe_img_src(src: &str) -> bool {
    let s = src.trim();
    s.starts_with("data:image/") || s.starts_with("https://") || s.starts_with("http://") || s.starts_with("/static") || s.starts_with('/')
}

/// HTML text escape.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape a value destined for an inline CSS/attribute context: strip the
/// characters that could break out of the `style="..."`/`src="..."` quote.
fn esc_attr(s: &str) -> String {
    s.chars().filter(|c| !matches!(c, '"' | '<' | '>' | '\\')).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banded_report::layout::lay_out;
    use crate::banded_report::model::*;

    fn one_field_layout() -> ReportLayout {
        let mut l = ReportLayout::default();
        l.bands.detail = Band {
            height: 20.0,
            elements: vec![Element {
                id: "d".into(),
                kind: "field".into(),
                x: 5.0,
                y: 2.0,
                w: 100.0,
                h: 16.0,
                expr: Some("$F{name}".into()),
                ..Default::default()
            }],
            print_when: None,
        };
        l
    }

    #[test]
    fn renders_positioned_html_and_escapes() {
        let l = one_field_layout();
        let mut r = BTreeMap::new();
        r.insert("name".to_string(), "<b>Acme & Co</b>".to_string());
        let rows = vec![r];
        let laid = lay_out(&l, &rows, &BTreeMap::new());
        let html = render_html(&l, &laid, &rows, &BTreeMap::new());
        assert!(html.contains("@page"));
        assert!(html.contains("position:absolute"));
        assert!(html.contains("&lt;b&gt;Acme &amp; Co&lt;/b&gt;"));
        // Absolute left = content_left(36) + el.x(5) = 41pt.
        assert!(html.contains("left:41pt"));
    }

    #[test]
    fn print_when_hides_element() {
        let mut l = one_field_layout();
        l.bands.detail.elements[0].print_when = Some("false".into());
        let mut r = BTreeMap::new();
        r.insert("name".to_string(), "SECRETVALUE".to_string());
        let rows = vec![r];
        let laid = lay_out(&l, &rows, &BTreeMap::new());
        let html = render_html(&l, &laid, &rows, &BTreeMap::new());
        assert!(!html.contains("SECRETVALUE"));
    }

    #[test]
    fn unsafe_image_src_dropped() {
        assert!(!safe_img_src("javascript:alert(1)"));
        assert!(safe_img_src("data:image/png;base64,AAAA"));
        assert!(safe_img_src("https://x/y.png"));
    }

    #[test]
    fn qr_barcode_renders_svg() {
        let mut l = one_field_layout();
        l.bands.detail.elements[0].kind = "barcode".into();
        l.bands.detail.elements[0].expr = Some("\"HELLO\"".into());
        l.bands.detail.elements[0].barcode = Some(Barcode { symbology: "qr".into() });
        let rows = vec![BTreeMap::new()];
        let laid = lay_out(&l, &rows, &BTreeMap::new());
        let html = render_html(&l, &laid, &rows, &BTreeMap::new());
        assert!(html.contains("<svg"));
    }
}
