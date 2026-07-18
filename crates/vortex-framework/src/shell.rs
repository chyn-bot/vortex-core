//! The standard application page shell.
//!
//! Every full-page host handler used to inline its own copy of the outer
//! chrome — `<!doctype>`, the `<head>` asset links, the theme-init script, the
//! mobile top bar, and the `flex` + sidebar + `<main>` wrapper. There were ~13
//! divergent copies, so a change to (say) an asset version or the mobile bar
//! had to be hand-propagated and drifted. [`render_app_shell`] is the single
//! source for that chrome; a handler now supplies only the `<title>`, the
//! already-rendered sidebar (see [`crate::build_sidebar`]), and the `<main>`
//! body — plus optional `<head>` and end-of-body escape hatches.
//!
//! The sidebar itself is passed in (not built here) so this stays decoupled
//! from `AppState`/`PluginRegistry`; callers already hold a sidebar string.

/// Render a full page using the standard shell with no extras.
/// `title` is the full `<title>` text; `sidebar` is the rendered `<aside>`
/// from [`crate::build_sidebar`]; `body` is the inner HTML of `<main>`.
pub fn render_app_shell(title: &str, sidebar: &str, body: &str) -> String {
    render_app_shell_with(title, sidebar, body, "", "")
}

/// Render a full page using the standard shell.
///
/// `head_extra` is injected just before `</head>` (page-specific `<link>`/
/// `<script>` tags such as htmx or a page stylesheet). `body_end` is injected
/// after the layout and before `</body>` (modals, page scripts). Both may be
/// empty. The mobile top bar carries the theme toggle and is `lg:hidden`, so it
/// affects only the mobile viewport.
pub fn render_app_shell_with(
    title: &str,
    sidebar: &str,
    body: &str,
    head_extra: &str,
    body_end: &str,
) -> String {
    format!(
        r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="vortex-idle" content="900">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=20" rel="stylesheet"/>
<script src="/static/vortex.js?v=20" defer></script>
<link href="/static/tailwind.css?v=21" rel="stylesheet"/>
{head_extra}</head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}<main class="flex-1 p-4 lg:p-6 min-w-0">{body}</main></div>{body_end}</body></html>"#,
        title = title,
        head_extra = head_extra,
        sidebar = sidebar,
        body = body,
        body_end = body_end,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_body_and_sidebar_in_canonical_chrome() {
        let html = render_app_shell("Reports - Remicle", "<aside id=\"sidebar\">S</aside>", "<h1>Hi</h1>");
        // Structural landmarks the whole app depends on.
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<title>Reports - Remicle</title>"));
        assert!(html.contains(r#"<aside id="sidebar">S</aside>"#));
        assert!(html.contains(r#"<main class="flex-1 p-4 lg:p-6 min-w-0"><h1>Hi</h1></main>"#));
        // Mobile bar + its theme toggle + the overlay that the bar toggles.
        assert!(html.contains("lg:hidden"));
        assert!(html.contains("theme-icon-sun"));
        assert!(html.contains(r#"id="sidebar-overlay""#));
        assert!(html.ends_with("</body></html>"));
    }

    #[test]
    fn head_and_body_extras_land_in_the_right_slots() {
        let html = render_app_shell_with(
            "T",
            "SB",
            "BODY",
            r#"<script src="/static/vendor/htmx.min.js"></script>"#,
            r#"<div id="modal"></div>"#,
        );
        // head_extra sits before </head>, after the standard assets.
        let head = &html[..html.find("</head>").unwrap()];
        assert!(head.contains("tailwind.css"));
        assert!(head.contains("htmx.min.js"));
        // body_end sits after the layout, before </body>.
        assert!(html.contains(r#"</main></div><div id="modal"></div></body></html>"#));
    }
}
