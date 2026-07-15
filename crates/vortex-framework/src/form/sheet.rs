//! The canonical record-form "sheet".
//!
//! Every record form — the generic Blueprint form, the config-driven
//! [`render_form`](super::render_form), and (over time) the bespoke plugin
//! forms — should present as a single centered Odoo-style *sheet*: one bordered
//! container holding the whole form as flat labelled field groups, an optional
//! control row (status bar / stage buttons) above it, and a Cancel/Save footer
//! below. Before this module each form inlined its own wrapper — `max-w-5xl`
//! cards floating on the page background, widths drifting between screens.
//! [`render_form_sheet`] is the single source for that chrome so a change to the
//! width, border, or spacing lands everywhere at once.
//!
//! The primitive is deliberately layout-only: callers own their `<form>`
//! attributes, field markup, footer buttons, and any below-form panels
//! (chatter/history), so it fits both the schema-driven forms and hand-rolled
//! plugin forms without prescribing their internals.

use crate::ui::html_escape;

/// Default sheet width. Wide enough to fill a laptop/desktop main column
/// without stranding a lot of empty gutter, while still capping line length so
/// a two-column field grid stays readable. Callers may pass their own width to
/// [`render_form_sheet`] when a form needs to be narrower or wider.
pub const SHEET_WIDTH: &str = "max-w-6xl";

/// Render one flat field group inside a sheet: an uppercase heading with an
/// underline rule, then `fields_html` laid out on a responsive two-column grid.
///
/// Pass an empty `heading` to omit the heading — e.g. a single-section form
/// where a heading would just duplicate the sheet title. `fields_html` is
/// emitted verbatim (the caller has already escaped its field labels/values);
/// `heading` is HTML-escaped here.
pub fn form_section(heading: &str, fields_html: &str) -> String {
    let head = if heading.is_empty() {
        String::new()
    } else {
        format!(
            r#"<h2 class="text-xs font-semibold uppercase tracking-wider text-base-content/50 border-b border-base-300 pb-2 mb-4">{}</h2>"#,
            html_escape(heading)
        )
    };
    format!(
        r#"<section class="break-inside-avoid mb-8 last:mb-0">{head}<div class="grid grid-cols-1 md:grid-cols-2 gap-x-6">{fields}</div></section>"#,
        head = head,
        fields = fields_html,
    )
}

/// The pieces of a record-form sheet. Every string is emitted verbatim except
/// where noted, so callers stay in control of their own escaping and markup.
pub struct FormSheet<'a> {
    /// Max-width utility class for the centered container, e.g. [`SHEET_WIDTH`].
    pub max_width: &'a str,
    /// List/back URL. When non-empty a "← Back" ghost link renders above the
    /// sheet; pass `""` when the caller already has its own header/breadcrumb.
    pub back_href: &'a str,
    /// Control row rendered above the sheet — typically a status bar plus
    /// stage-transition buttons. `""` to omit.
    pub control_row: &'a str,
    /// Attributes for the `<form>` element, inserted as `<form {form_attrs}>`
    /// (e.g. `r#"method="post" action="/contacts/42" id="record-form""#`). The
    /// form wraps both the sheet and the footer so a plain submit works.
    pub form_attrs: &'a str,
    /// Sheet title, rendered as an `<h1>` inside the container. HTML-escaped.
    pub title: &'a str,
    /// Inner form body — the field groups (see [`form_section`]), already
    /// composed into whatever column arrangement the caller wants. Verbatim.
    pub inner: &'a str,
    /// Footer buttons row (Cancel/Save …), placed inside the form below the
    /// sheet. Verbatim. `""` to omit the footer entirely.
    pub footer: &'a str,
    /// Content below the form — chatter/history panels. Verbatim. `""` to omit.
    pub below: &'a str,
}

/// Render a [`FormSheet`] into the canonical centered layout.
pub fn render_form_sheet(s: &FormSheet<'_>) -> String {
    let back = if s.back_href.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="mb-3"><a href="{href}" class="btn btn-ghost btn-sm">← Back</a></div>"#,
            href = s.back_href,
        )
    };
    let footer = if s.footer.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="flex justify-end gap-2 mt-4">{}</div>"#, s.footer)
    };
    let below = if s.below.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="mt-8 flex flex-col gap-6">{}</div>"#, s.below)
    };
    format!(
        r##"<div class="{maxw} mx-auto">
{back}{control}
<form {attrs}>
    <div class="bg-base-100 rounded-lg shadow-sm border border-base-300 p-6 md:p-8">
        <h1 class="text-2xl font-bold mb-6">{title}</h1>
        {inner}
    </div>
    {footer}
</form>
{below}
</div>"##,
        maxw = s.max_width,
        back = back,
        control = s.control_row,
        attrs = s.form_attrs,
        title = html_escape(s.title),
        inner = s.inner,
        footer = footer,
        below = below,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_omits_heading_when_empty() {
        let s = form_section("", r#"<input name="x"/>"#);
        assert!(!s.contains("<h2"));
        assert!(s.contains(r#"<input name="x"/>"#));
        assert!(s.contains("md:grid-cols-2"));
    }

    #[test]
    fn section_escapes_heading() {
        let s = form_section("A & B", "");
        assert!(s.contains("A &amp; B"));
    }

    #[test]
    fn sheet_wires_all_slots_and_escapes_title() {
        let html = render_form_sheet(&FormSheet {
            max_width: SHEET_WIDTH,
            back_href: "/list/x",
            control_row: "<div id=\"bar\"></div>",
            form_attrs: r#"method="post" action="/form/x/1""#,
            title: "Edit <X>",
            inner: "<section>F</section>",
            footer: r#"<button>Save</button>"#,
            below: "<div>chatter</div>",
        });
        assert!(html.contains("max-w-6xl mx-auto"));
        assert!(html.contains(r#"href="/list/x""#));
        assert!(html.contains(r#"<div id="bar"></div>"#));
        assert!(html.contains(r#"<form method="post" action="/form/x/1">"#));
        assert!(html.contains("Edit &lt;X&gt;")); // title escaped
        assert!(html.contains("<section>F</section>"));
        assert!(html.contains("<button>Save</button>"));
        assert!(html.contains("<div>chatter</div>"));
    }

    #[test]
    fn sheet_drops_optional_slots_when_empty() {
        let html = render_form_sheet(&FormSheet {
            max_width: SHEET_WIDTH,
            back_href: "",
            control_row: "",
            form_attrs: "method=\"post\"",
            title: "T",
            inner: "I",
            footer: "",
            below: "",
        });
        assert!(!html.contains("← Back"));
        assert!(!html.contains("justify-end")); // no footer row
        assert!(!html.contains("mt-8")); // no below block
    }
}
