//! Rich-text sanitization for user-authored quote text.
//!
//! Quote line descriptions and the header Title / Summary / Note may carry
//! inline formatting (bold, italic, underline, font size, colour) entered in
//! the editor's WYSIWYG fields. Because that HTML is authored by a user and
//! later rendered **raw** (into the record page and the printed PDF), it MUST
//! be run through a strict allow-list before it is stored — anything outside
//! the allow-list (scripts, event handlers, links, arbitrary CSS) is dropped.
//!
//! We lean on `ammonia` (html5ever-based, the standard Rust sanitizer) for the
//! tag/attribute structure and add a CSS property filter for the one attribute
//! we permit — `style` — so only a closed set of visual properties survive.

use std::collections::{HashMap, HashSet};

/// The visual CSS properties a user may set. Everything else in a `style`
/// attribute is discarded. None of these can execute script or load a
/// resource, which is what keeps raw rendering safe.
const ALLOWED_STYLE_PROPS: &[&str] = &[
    "color",
    "background-color",
    "font-size",
    "font-weight",
    "font-style",
    // Browsers' execCommand('underline') emits the longhand `text-decoration-line`;
    // keep the shorthand too for hand-authored / pasted content.
    "text-decoration",
    "text-decoration-line",
    "text-align",
    // Table presentation (inserted tables carry inline styling so they render
    // identically in the editor, the record page, and the printed PDF).
    "border",
    "border-color",
    "border-width",
    "border-style",
    "border-collapse",
    "padding",
    "width",
    "vertical-align",
];

/// Sanitize user rich text to a safe HTML fragment.
///
/// Allows only inline formatting tags plus a filtered `style` attribute. The
/// result is safe to embed raw in trusted markup. Empty in → empty out.
pub fn sanitize_rich(html: &str) -> String {
    if html.trim().is_empty() {
        return String::new();
    }

    let tags: HashSet<&str> = [
        "b", "strong", "i", "em", "u", "s", "span", "p", "div", "br", // inline formatting
        "table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "colgroup", "col", // tables
    ]
    .into_iter()
    .collect();

    // `style` is permitted (and filtered) on the container-ish and table tags;
    // table cells additionally keep the numeric span attributes.
    let mut tag_attributes: HashMap<&str, HashSet<&str>> = HashMap::new();
    for t in ["span", "p", "div", "table", "thead", "tbody", "tfoot", "tr", "caption", "colgroup", "col"] {
        tag_attributes.insert(t, ["style"].into_iter().collect());
    }
    for t in ["td", "th"] {
        tag_attributes.insert(t, ["style", "colspan", "rowspan"].into_iter().collect());
    }

    ammonia::Builder::default()
        .tags(tags)
        .tag_attributes(tag_attributes)
        // No links, no images, no url()-bearing anything.
        .url_schemes(HashSet::new())
        .generic_attributes(HashSet::new())
        // Rewrite (or drop) each attribute value. Only `style` reaches here.
        .attribute_filter(|_element, attribute, value| match attribute {
            "style" => {
                let cleaned = sanitize_style(value);
                if cleaned.is_empty() {
                    None
                } else {
                    Some(cleaned.into())
                }
            }
            // colspan / rowspan: keep only a small positive integer.
            "colspan" | "rowspan" => match value.trim().parse::<u32>() {
                Ok(n) if (1..=99).contains(&n) => Some(n.to_string().into()),
                _ => None,
            },
            _ => Some(value.into()),
        })
        .clean(html)
        .to_string()
}

/// Keep only allow-listed CSS declarations whose values pass a strict check.
/// Produces a normalized `prop: value; …` string (possibly empty).
fn sanitize_style(style: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for decl in style.split(';') {
        let mut parts = decl.splitn(2, ':');
        let (Some(prop), Some(val)) = (parts.next(), parts.next()) else {
            continue;
        };
        let prop = prop.trim().to_ascii_lowercase();
        let val = val.trim();
        if !ALLOWED_STYLE_PROPS.contains(&prop.as_str()) {
            continue;
        }
        if is_safe_css_value(val) {
            out.push(format!("{prop}: {val}"));
        }
    }
    out.join("; ")
}

/// A CSS value is safe only if it is a short token made of an inert character
/// set — letters, digits, `#`, `%`, `.`, `,`, spaces, `(`, `)` for `rgb()`.
/// This rejects `url(...)`, `expression(...)`, escapes, and anything that could
/// smuggle a resource load or script.
fn is_safe_css_value(val: &str) -> bool {
    if val.is_empty() || val.len() > 64 {
        return false;
    }
    let lower = val.to_ascii_lowercase();
    if lower.contains("url")
        || lower.contains("expression")
        || lower.contains("javascript")
        || lower.contains("/*")
        || lower.contains("\\")
        || lower.contains('&')
    {
        return false;
    }
    val.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '#' | '%' | '.' | ',' | ' ' | '(' | ')' | '-'))
}

/// Reduce rich text to plain text (tags stripped, entities decoded enough for
/// display). Used where only plain text is valid — e.g. the accounting
/// invoice-line description, which is a bounded VARCHAR.
pub fn strip_tags(html: &str) -> String {
    // Sanitize to the allow-list first (so we start from well-formed markup),
    // then drop every tag, collapsing to readable plain text.
    let safe = sanitize_rich(html);
    let mut out = String::with_capacity(safe.len());
    let mut in_tag = false;
    for c in safe.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    // Decode the handful of entities the sanitizer may emit.
    let out = out
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ");
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_basic_formatting() {
        let out = sanitize_rich("<b>Bold</b> <i>italic</i> <u>underline</u>");
        assert!(out.contains("<b>Bold</b>"));
        assert!(out.contains("<i>italic</i>"));
        assert!(out.contains("<u>underline</u>"));
    }

    #[test]
    fn strips_scripts_and_handlers() {
        let out = sanitize_rich(r#"<span onclick="alert(1)">x</span><script>alert(2)</script>"#);
        assert!(!out.contains("script"));
        assert!(!out.contains("onclick"));
        assert!(out.contains('x'));
    }

    #[test]
    fn keeps_safe_style_props_only() {
        let out = sanitize_rich(
            r#"<span style="color: #ff0000; font-size: 18px; position: fixed;">hi</span>"#,
        );
        assert!(out.contains("color: #ff0000"));
        assert!(out.contains("font-size: 18px"));
        assert!(!out.contains("position"));
    }

    #[test]
    fn rejects_url_and_expression_in_css() {
        let out = sanitize_rich(
            r#"<span style="background-color: url(javascript:alert(1)); color: red;">x</span>"#,
        );
        assert!(!out.to_lowercase().contains("url"));
        assert!(!out.to_lowercase().contains("javascript"));
        assert!(out.contains("color: red"));
    }

    #[test]
    fn keeps_browser_execcommand_output() {
        // The exact HTML Chrome/Firefox produce via execCommand + styleWithCSS.
        for (raw, needle) in [
            (r#"<span style="font-weight: bold;">x</span>"#, "font-weight: bold"),
            (r#"<span style="font-style: italic;">x</span>"#, "font-style: italic"),
            (r#"<span style="text-decoration-line: underline;">x</span>"#, "text-decoration-line: underline"),
            (r#"<span style="font-size: x-large;">x</span>"#, "font-size: x-large"),
            (r#"<span style="color: rgb(255, 0, 0);">x</span>"#, "color: rgb(255, 0, 0)"),
        ] {
            let out = sanitize_rich(raw);
            assert!(out.contains(needle), "expected {needle:?} to survive, got {out:?}");
        }
    }

    #[test]
    fn drops_links() {
        let out = sanitize_rich(r#"<a href="http://evil.test">click</a>"#);
        assert!(!out.contains("href"));
        assert!(!out.contains("<a"));
        assert!(out.contains("click"));
    }

    #[test]
    fn strip_tags_to_plain() {
        assert_eq!(strip_tags("<b>Hello</b> <i>world</i>"), "Hello world");
        assert_eq!(strip_tags(""), "");
    }

    #[test]
    fn keeps_tables() {
        let raw = r#"<table style="border-collapse: collapse; width: 100%"><tbody><tr><td style="border: 1px solid #ccc; padding: 4px" colspan="2">Cell</td></tr></tbody></table>"#;
        let out = sanitize_rich(raw);
        assert!(out.contains("<table"), "got {out:?}");
        assert!(out.contains("<td"));
        assert!(out.contains("colspan=\"2\""));
        assert!(out.contains("border-collapse: collapse"));
        assert!(out.contains("padding: 4px"));
    }

    #[test]
    fn rejects_bad_colspan_and_onmouseover_in_table() {
        let out = sanitize_rich(
            r#"<table><tr><td colspan="abc" onmouseover="x()">a</td></tr></table>"#,
        );
        assert!(!out.contains("colspan"), "bad colspan should be dropped: {out:?}");
        assert!(!out.contains("onmouseover"));
        assert!(out.contains("<td"));
    }
}
