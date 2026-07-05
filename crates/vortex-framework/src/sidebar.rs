//! Sidebar renderer — assembles the left-hand navigation from core
//! items plus plugin-contributed entries.
//!
//! The host binary calls [`build_sidebar`] from every HTML-returning
//! handler to produce the consistent sidebar shell. Plugins that
//! want a menu entry never touch this code — they implement
//! `Plugin::menu_entries` and the registry gets queried here.
//!
//! ## What lives where
//!
//! - **Hardcoded in this function**: the core items that predate
//!   any plugin — home, dashboard, contacts, the admin Users /
//!   Companies / Roles / Access Control / Settings block, and the
//!   System Administrator tools (Audit Log). These are the host's
//!   own screens and they ship with `vortex-cli` itself.
//! - **From the plugin registry**: everything else. Each installed
//!   plugin contributes `Vec<MenuEntry>` via `menu_entries()`; the
//!   registry aggregates and filters by install state and role;
//!   this function renders each entry inline.
//!
//! ## Rendering choices
//!
//! Plugin icons are declared as icon *names* in `MenuEntry::icon`,
//! not as raw SVG. This renderer maps a small set of names to
//! inline SVG paths via [`icon_svg_path`]. Unknown names fall back
//! to a neutral circle placeholder. A future phase can externalize
//! the icon set.

use std::collections::HashSet;

use crate::menu::MenuGroup;
use crate::registry::PluginRegistry;
use crate::ui::html_escape;

/// Render the complete sidebar HTML as a string.
///
/// `active_page` matches either a core page key (`"home"`,
/// `"dashboard"`, `"contacts"`) or a plugin menu-entry id
/// (e.g. `"crm.leads"`). Matching entries render with the
/// `active` CSS class.
pub fn build_sidebar(
    active_page: &str,
    user_name: &str,
    initials: &str,
    installed: &HashSet<String>,
    is_admin: bool,
    plugin_registry: &PluginRegistry,
    user_roles: &[String],
) -> String {
    let mut nav_html = String::new();

    // ─── Core items (host-owned) ───────────────────────────────
    let active = if active_page == "home" { " active" } else { "" };
    nav_html.push_str(&format!(r##"<li><a href="/home" class="{}"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>Home</a></li>"##, active));

    // Approvals inbox — visible to all; the page itself shows only the
    // requests this user may act on (empty for users who never approve).
    let active = if active_page == "approvals" { " active" } else { "" };
    nav_html.push_str(&format!(r##"<li><a href="/approvals" class="{}"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>Approvals</a></li>"##, active));

    // Reports hub — visible to all; the page shows only reports the user may run.
    let active = if active_page == "reports" { " active" } else { "" };
    nav_html.push_str(&format!(r##"<li><a href="/reports" class="{}"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-6h13M9 5h13M5 5h.01M5 11h.01M5 17h.01"/></svg>Reports</a></li>"##, active));

    if is_admin {
        let active = if active_page == "dashboard" { " active" } else { "" };
        nav_html.push_str(&format!(r##"<li><a href="/dashboard" class="{}"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>Dashboard</a></li>"##, active));

        let active = if active_page == "audit" { " active" } else { "" };
        nav_html.push_str(&format!(r##"<li><a href="/audit" class="{}"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/></svg>Audit Log</a></li>"##, active));

        let active = if active_page == "users" { " active" } else { "" };
        nav_html.push_str(&format!(r##"<li><a href="/users" class="{}"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m9 5.197v-1"/></svg>Users</a></li>"##, active));

        let active = if active_page == "settings" { " active" } else { "" };
        nav_html.push_str(&format!(r##"<li><a href="/settings" class="{}"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>Settings</a></li>"##, active));
    }

    // NOTE: the legacy hardcoded `if installed.contains("contacts")`
    // check used to live here, special-casing one module inside the
    // framework. It was removed in Phase 0.6 — the host binary now
    // registers a synthetic `ContactsBuiltinPlugin` that feeds the
    // normal plugin menu_entries path, so the framework has no
    // plugin-specific knowledge. If you're tempted to add another
    // `if installed.contains(...)` here, register a plugin instead.

    // ─── Plugin-contributed operational entries ────────────────
    let ops_entries =
        plugin_registry.collect_menu_by_group(MenuGroup::Operations, installed, user_roles);

    // Group by plugin technical name (derived from the entry id prefix)
    // so related entries render together under a per-plugin header.
    let mut ops_by_plugin: std::collections::BTreeMap<String, Vec<&crate::menu::MenuEntry>> =
        std::collections::BTreeMap::new();
    for entry in &ops_entries {
        let prefix = entry.id.split('.').next().unwrap_or("").to_string();
        ops_by_plugin.entry(prefix).or_default().push(entry);
    }

    for (plugin_key, entries) in &ops_by_plugin {
        let section_title = pretty_section_title(plugin_key, plugin_registry);
        nav_html.push_str(&format!(
            r#"<li class="menu-title mt-4"><span>{}</span></li>"#,
            html_escape(&section_title)
        ));

        // A child entry (`parent` set to a sibling's id within the same
        // section) renders nested under that parent as a collapsible
        // sub-menu rather than as a top-level item. Index parents →
        // children first; entries are already priority-sorted so child
        // order is preserved.
        let toplevel_ids: HashSet<&str> = entries
            .iter()
            .filter(|e| e.parent.is_none())
            .map(|e| e.id.as_str())
            .collect();
        let mut children: std::collections::BTreeMap<&str, Vec<&crate::menu::MenuEntry>> =
            std::collections::BTreeMap::new();
        for e in entries {
            if let Some(p) = e.parent.as_deref() {
                if toplevel_ids.contains(p) {
                    children.entry(p).or_default().push(e);
                }
            }
        }

        for entry in entries {
            // Children are emitted inside their parent's sub-menu below;
            // skip them here. An entry whose `parent` doesn't resolve to a
            // sibling falls through and renders as a normal top-level item.
            if let Some(p) = entry.parent.as_deref() {
                if toplevel_ids.contains(p) {
                    continue;
                }
            }
            match children.get(entry.id.as_str()) {
                Some(kids) => render_submenu(&mut nav_html, entry, kids, active_page),
                None => render_leaf(&mut nav_html, entry, active_page),
            }
        }
    }

    format!(r##"<aside id="sidebar" class="w-64 bg-base-100 shadow-lg flex flex-col fixed top-0 left-0 z-40 h-full -translate-x-full transition-transform duration-200 lg:translate-x-0 lg:sticky lg:top-0 lg:h-screen lg:self-start overflow-y-auto">
<div class="p-4 border-b border-base-300"><a href="/home" class="text-xl font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a></div>
<nav class="flex-1 p-4 overflow-y-auto"><ul class="menu menu-sm gap-1">{}</ul></nav>
<div class="p-4 border-t border-base-300"><div class="flex items-center gap-3">
<div class="avatar placeholder"><div class="bg-primary text-primary-content rounded-full w-10"><span>{}</span></div></div>
<div class="flex-1 min-w-0"><p class="font-medium truncate">{}</p></div>
<button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square" title="Toggle theme"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button>
<form action="/auth/logout" method="POST"><button type="submit" class="btn btn-ghost btn-sm">Logout</button></form>
</div></div>
</aside>"##, nav_html, initials, user_name)
}

/// Turn a technical name like `"field_service"` into a display
/// title like `"Field Service"`, using the plugin registry to look
/// up the plugin's preferred display name if one is registered.
fn pretty_section_title(plugin_key: &str, registry: &PluginRegistry) -> String {
    if registry.technical_names().contains(&plugin_key) {
        // Title-case the technical name.
        plugin_key
            .replace('_', " ")
            .split_whitespace()
            .map(|w| {
                let mut c = w.chars();
                match c.next() {
                    Some(ch) => ch.to_uppercase().collect::<String>() + c.as_str(),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        "Modules".to_string()
    }
}

/// Render a single navigable leaf `<li><a>` entry, marking it active
/// when its id matches the current page.
fn render_leaf(nav: &mut String, entry: &crate::menu::MenuEntry, active_page: &str) {
    let active = if entry.id == active_page { " active" } else { "" };
    nav.push_str(&format!(
        r#"<li><a href="{}" class="{}">{}{}</a></li>"#,
        html_escape(&entry.url),
        active,
        icon_svg_el(entry.icon.as_deref()),
        html_escape(&entry.label),
    ));
}

/// Render a parent entry that owns `kids` as a collapsible DaisyUI
/// sub-menu (`<details><summary>…</summary><ul>…</ul></details>`). The
/// branch opens automatically when the parent or any child is the active
/// page, so a deep link lands with the relevant section expanded.
fn render_submenu(
    nav: &mut String,
    parent: &crate::menu::MenuEntry,
    kids: &[&crate::menu::MenuEntry],
    active_page: &str,
) {
    let branch_active = parent.id == active_page || kids.iter().any(|k| k.id == active_page);
    let open = if branch_active { " open" } else { "" };
    let summary_active = if parent.id == active_page { " active" } else { "" };
    nav.push_str(&format!(
        r#"<li><details{}><summary class="{}">{}{}</summary><ul>"#,
        open,
        summary_active,
        icon_svg_el(parent.icon.as_deref()),
        html_escape(&parent.label),
    ));
    for k in kids {
        render_leaf(nav, k, active_page);
    }
    nav.push_str("</ul></details></li>");
}

/// Wrap an optional icon name in the standard inline `<svg>` element,
/// falling back to a neutral circle when the name is missing or unknown.
fn icon_svg_el(icon: Option<&str>) -> String {
    let body = icon.map(icon_svg_path).unwrap_or_else(
        || r#"<circle cx="12" cy="12" r="9" stroke-width="2" fill="none"/>"#.to_string(),
    );
    format!(
        r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">{}</svg>"#,
        body
    )
}

/// Map a short icon name to an inline SVG `path` element body. Kept
/// deliberately small for now; a future phase can externalize this to
/// a data file or use a proper icon set.
fn icon_svg_path(name: &str) -> String {
    let path = match name {
        "building" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/>"#,
        "map-pin" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"/>"#,
        "bolt" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>"#,
        "cube" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/>"#,
        "globe" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>"#,
        "clipboard-list" | "clipboard-check" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>"#,
        "check-circle" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>"#,
        "calendar" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>"#,
        "diagram" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/><circle cx="17" cy="18" r="3" stroke-width="2" fill="none"/>"#,
        "chart" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>"#,
        "factory" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/>"#,
        "cog" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>"#,
        "tag" => r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2 7l5-5h7a2 2 0 012 2v7l-5 5-9-9z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6.5 6.5h.01"/>"#,
        _ => r#"<circle cx="12" cy="12" r="9" stroke-width="2" fill="none"/>"#,
    };
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::menu::MenuEntry;
    use crate::plugin::Plugin;
    use axum::Router;
    use std::sync::Arc;

    struct Dummy;
    #[async_trait::async_trait]
    impl Plugin for Dummy {
        fn technical_name(&self) -> &'static str {
            "field_service"
        }
        fn display_name(&self) -> &'static str {
            "Field Service"
        }
        fn version(&self) -> &'static str {
            "0.1.0"
        }
        fn routes(&self) -> Router<Arc<crate::AppState>> {
            Router::new()
        }
        fn menu_entries(&self) -> Vec<MenuEntry> {
            vec![MenuEntry::new(
                "field_service.leads",
                "Leads",
                "/crm/leads",
                MenuGroup::Operations,
            )]
        }
    }

    #[test]
    fn sidebar_renders_plugin_entry() {
        let mut r = PluginRegistry::new();
        r.register(Arc::new(Dummy));
        let installed: HashSet<String> = ["field_service".to_string()].into_iter().collect();
        let html = build_sidebar("home", "Alice", "AL", &installed, true, &r, &[]);
        assert!(html.contains("Leads"));
        assert!(html.contains("Field Service"));
        assert!(html.contains("/crm/leads"));
    }

    #[test]
    fn sidebar_skips_uninstalled_plugin() {
        let mut r = PluginRegistry::new();
        r.register(Arc::new(Dummy));
        let installed: HashSet<String> = HashSet::new();
        let html = build_sidebar("home", "Alice", "AL", &installed, true, &r, &[]);
        assert!(!html.contains("Leads"));
    }

    #[test]
    fn sidebar_always_has_home_link() {
        let r = PluginRegistry::new();
        let html = build_sidebar("home", "Alice", "AL", &HashSet::new(), false, &r, &[]);
        assert!(html.contains(r#"href="/home""#));
    }

    struct NestedPlugin;
    #[async_trait::async_trait]
    impl Plugin for NestedPlugin {
        fn technical_name(&self) -> &'static str {
            "inventory"
        }
        fn display_name(&self) -> &'static str {
            "Inventory"
        }
        fn version(&self) -> &'static str {
            "0.1.0"
        }
        fn routes(&self) -> Router<Arc<crate::AppState>> {
            Router::new()
        }
        fn menu_entries(&self) -> Vec<MenuEntry> {
            vec![
                MenuEntry::new("inventory.config", "Configuration", "#", MenuGroup::Operations)
                    .with_priority(90),
                MenuEntry::new(
                    "inventory.categories",
                    "Product Categories",
                    "/inventory/categories",
                    MenuGroup::Operations,
                )
                .with_priority(91)
                .under("inventory.config"),
            ]
        }
    }

    #[test]
    fn sidebar_nests_child_in_collapsible_submenu() {
        let mut r = PluginRegistry::new();
        r.register(Arc::new(NestedPlugin));
        let installed: HashSet<String> = ["inventory".to_string()].into_iter().collect();
        let html = build_sidebar("home", "Alice", "AL", &installed, true, &r, &[]);
        // Parent rendered as a <details> submenu, child link nested inside it.
        assert!(html.contains("<details"));
        assert!(html.contains("<summary"));
        let det = html.find("<details").expect("submenu present");
        let child = html.find("/inventory/categories").expect("child link present");
        assert!(child > det, "child must render inside the parent submenu");
    }

    #[test]
    fn sidebar_opens_submenu_when_descendant_active() {
        let mut r = PluginRegistry::new();
        r.register(Arc::new(NestedPlugin));
        let installed: HashSet<String> = ["inventory".to_string()].into_iter().collect();
        // Collapsed when elsewhere…
        let html = build_sidebar("home", "Alice", "AL", &installed, true, &r, &[]);
        assert!(!html.contains("<details open"));
        // …auto-opens when the active page is a child of the submenu.
        let html = build_sidebar("inventory.categories", "Alice", "AL", &installed, true, &r, &[]);
        assert!(html.contains("<details open"));
    }
}
