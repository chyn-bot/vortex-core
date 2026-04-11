//! Plugin registry: the aggregation point the host walks at startup.
//!
//! The host binary builds a [`PluginRegistry`], registers each
//! installed plugin into it, and then asks the registry for:
//!
//! - `build_router(base)` — merges every plugin's routes onto a
//!   host-provided base router. Returns the full composite router.
//! - `collect_menu(installed_modules, user_roles)` — aggregates every
//!   plugin's menu entries into a single ordered list, filtered by
//!   install state and user permissions.
//! - `run_startup_hooks(state)` — calls each plugin's `on_startup`
//!   hook in registration order. Fails fast on the first error.
//!
//! The registry is built once during server startup. Subsequent route
//! and menu queries read from it concurrently. Hot-reload of plugins
//! is out of scope for Phase 0.3; the registry is effectively immutable
//! after startup.

use std::collections::HashSet;
use std::sync::Arc;

use axum::Router;
use tracing::{info, warn};
use vortex_common::VortexResult;

use crate::menu::{MenuEntry, MenuGroup};
use crate::plugin::Plugin;
use crate::state::AppState;

/// Central registry of installed plugins.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Arc<dyn Plugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a plugin. Call this for every plugin the host wishes to
    /// load, in dependency order. The registry does not do dependency
    /// resolution itself — that remains the job of `vortex-module`'s
    /// `ModuleLoader`. This registry is purely the axum/UI binding.
    pub fn register(&mut self, plugin: Arc<dyn Plugin>) {
        info!(
            technical_name = plugin.technical_name(),
            display_name = plugin.display_name(),
            version = plugin.version(),
            "plugin registered"
        );
        self.plugins.push(plugin);
    }

    /// Return the list of registered plugin technical names.
    pub fn technical_names(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|p| p.technical_name()).collect()
    }

    /// Iterator over every registered plugin. Used by the host's
    /// router builder to call `nested_services()` on each plugin
    /// individually, since that method returns a list of `(prefix,
    /// Router)` pairs that need to be `nest_service`d one by one.
    pub fn plugins_iter(&self) -> impl Iterator<Item = &Arc<dyn Plugin>> {
        self.plugins.iter()
    }

    /// Return the number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Merge every plugin's routes onto the given base router.
    ///
    /// The host typically passes a base router containing its core
    /// routes (login, users, settings, audit, policy), and the
    /// registry merges each plugin's contribution on top. The result
    /// is the complete router the host binds to its HTTP listener.
    ///
    /// Conflicting routes (same method+path from two plugins) will
    /// cause axum's `merge` to panic at startup — which is the right
    /// behaviour, since silent conflicts would be a nightmare to
    /// diagnose.
    pub fn build_router(&self, mut base: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
        for plugin in &self.plugins {
            let name = plugin.technical_name();
            let fragment = plugin.routes();
            info!(plugin = name, "mounting plugin routes");
            base = base.merge(fragment);
        }
        base
    }

    /// Collect every plugin's menu entries into a single sorted list.
    ///
    /// Filtering:
    /// - Entries whose owning plugin is not in `installed` are dropped.
    ///   This handles the edge case where a plugin is compiled in but
    ///   not marked installed on the current tenant database.
    /// - Entries with a `required_role` that the user does not have
    ///   are dropped. Route handlers must still perform their own
    ///   authorization; this is only a UI hint.
    ///
    /// Sort order: group priority first (Main < Operations < …), then
    /// entry priority within each group, then label as a tie-breaker.
    pub fn collect_menu(
        &self,
        installed: &HashSet<String>,
        user_roles: &[String],
    ) -> Vec<MenuEntry> {
        let mut entries: Vec<MenuEntry> = Vec::new();
        let user_role_set: HashSet<&str> = user_roles.iter().map(|r| r.as_str()).collect();

        for plugin in &self.plugins {
            let name = plugin.technical_name();
            if !installed.contains(name) {
                continue;
            }
            for entry in plugin.menu_entries() {
                if let Some(required) = &entry.required_role {
                    if !user_role_set.contains(required.as_str()) {
                        continue;
                    }
                }
                entries.push(entry);
            }
        }

        entries.sort_by(|a, b| {
            a.group
                .priority()
                .cmp(&b.group.priority())
                .then_with(|| a.priority.cmp(&b.priority))
                .then_with(|| a.label.cmp(&b.label))
        });

        entries
    }

    /// Run every plugin's `on_startup` hook in registration order.
    /// Fails on the first error.
    pub async fn run_startup_hooks(&self, state: &AppState) -> VortexResult<()> {
        for plugin in &self.plugins {
            let name = plugin.technical_name();
            match plugin.on_startup(state).await {
                Ok(()) => {}
                Err(e) => {
                    warn!(plugin = name, error = %e, "plugin on_startup failed");
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Walk the aggregated menu and return only entries in the given
    /// group. Useful for sidebar renderers that want to lay out
    /// different groups in different places.
    pub fn collect_menu_by_group(
        &self,
        group: MenuGroup,
        installed: &HashSet<String>,
        user_roles: &[String],
    ) -> Vec<MenuEntry> {
        self.collect_menu(installed, user_roles)
            .into_iter()
            .filter(|e| e.group == group)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::menu::{MenuEntry, MenuGroup};
    use axum::routing::get;
    use std::collections::HashSet;

    struct TestPlugin {
        name: &'static str,
        entries: Vec<MenuEntry>,
    }

    #[async_trait::async_trait]
    impl Plugin for TestPlugin {
        fn technical_name(&self) -> &'static str {
            self.name
        }
        fn display_name(&self) -> &'static str {
            self.name
        }
        fn version(&self) -> &'static str {
            "0.1.0"
        }
        fn routes(&self) -> Router<Arc<AppState>> {
            Router::new().route(
                &format!("/{}/ping", self.name),
                get(|| async { "pong" }),
            )
        }
        fn menu_entries(&self) -> Vec<MenuEntry> {
            self.entries.clone()
        }
    }

    fn plugin(name: &'static str, entries: Vec<MenuEntry>) -> Arc<dyn Plugin> {
        Arc::new(TestPlugin { name, entries })
    }

    fn installed(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn registry_filters_uninstalled_plugins() {
        let mut r = PluginRegistry::new();
        r.register(plugin(
            "eam",
            vec![MenuEntry::new("eam.main", "EAM", "/eam", MenuGroup::Operations)],
        ));
        r.register(plugin(
            "cr",
            vec![MenuEntry::new("cr.main", "CRs", "/cr", MenuGroup::Operations)],
        ));
        let menu = r.collect_menu(&installed(&["eam"]), &[]);
        assert_eq!(menu.len(), 1);
        assert_eq!(menu[0].label, "EAM");
    }

    #[test]
    fn registry_filters_by_required_role() {
        let mut r = PluginRegistry::new();
        let entry = MenuEntry::new("eam.admin", "Admin", "/eam/admin", MenuGroup::Administration)
            .require_role("admin");
        r.register(plugin("eam", vec![entry]));
        let user_menu = r.collect_menu(&installed(&["eam"]), &["viewer".to_string()]);
        assert!(user_menu.is_empty());
        let admin_menu = r.collect_menu(&installed(&["eam"]), &["admin".to_string()]);
        assert_eq!(admin_menu.len(), 1);
    }

    #[test]
    fn registry_orders_by_group_then_priority() {
        let mut r = PluginRegistry::new();
        r.register(plugin(
            "eam",
            vec![
                MenuEntry::new("eam.a", "A", "/a", MenuGroup::Operations).with_priority(20),
                MenuEntry::new("eam.b", "B", "/b", MenuGroup::Operations).with_priority(10),
                MenuEntry::new("eam.c", "C", "/c", MenuGroup::Administration).with_priority(5),
            ],
        ));
        let menu = r.collect_menu(&installed(&["eam"]), &[]);
        assert_eq!(menu[0].label, "B"); // lowest priority in Operations
        assert_eq!(menu[1].label, "A");
        assert_eq!(menu[2].label, "C"); // Administration comes after Operations
    }

    #[test]
    fn collect_menu_by_group_filter() {
        let mut r = PluginRegistry::new();
        r.register(plugin(
            "eam",
            vec![
                MenuEntry::new("eam.a", "A", "/a", MenuGroup::Operations),
                MenuEntry::new("eam.b", "B", "/b", MenuGroup::Administration),
            ],
        ));
        let ops = r.collect_menu_by_group(MenuGroup::Operations, &installed(&["eam"]), &[]);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].label, "A");
    }

    #[test]
    fn registry_tracks_technical_names() {
        let mut r = PluginRegistry::new();
        r.register(plugin("eam", vec![]));
        r.register(plugin("cr", vec![]));
        assert_eq!(r.len(), 2);
        assert_eq!(r.technical_names(), vec!["eam", "cr"]);
    }
}
