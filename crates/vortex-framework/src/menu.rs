//! Menu entry types for plugin sidebar contributions.
//!
//! A `MenuEntry` is a single item a plugin contributes to the host's
//! sidebar navigation. The host aggregates entries from every installed
//! plugin, sorts them by priority within each group, and renders them
//! into whatever UI shell the host provides.
//!
//! ## Grouping
//!
//! Entries belong to named [`MenuGroup`]s so the host can lay out related
//! items together (e.g. all "Asset Management" entries under one header).
//! Groups have their own priority which controls the order of headers in
//! the sidebar.
//!
//! ## Required permissions
//!
//! Each entry may declare a `required_role`. Host sidebar rendering
//! filters out entries the current user does not have permission to see.
//! This is a UI filter only — route handlers must still perform their
//! own authorization checks (RBAC + Cedar policy), because clients can
//! bypass the sidebar and hit the URL directly.
//!
//! ## Why not Askama?
//!
//! The host binary owns the rendered HTML shape. Plugins declare
//! structured data (label, icon, URL) and the host's template decides
//! how to render it. This keeps plugin crates independent of the host's
//! UI framework — a future admin CLI or TUI can consume the same entries.

use serde::{Deserialize, Serialize};

/// A single entry in the sidebar. Plugins return a `Vec<MenuEntry>` from
/// `Plugin::menu_entries`; the host aggregates, filters, and renders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MenuEntry {
    /// Stable identifier used to mark the "active" entry during
    /// rendering. Format: `"<plugin>.<entry>"`, e.g. `"crm.leads"`.
    pub id: String,
    /// Display label. Plugins should use locale-neutral labels; the
    /// host may translate via an i18n layer in a future phase.
    pub label: String,
    /// URL this entry navigates to when clicked.
    pub url: String,
    /// Optional icon identifier. The host maps this to whatever icon
    /// system it uses (heroicons name, bootstrap icon class, inline
    /// SVG path — up to the host).
    pub icon: Option<String>,
    /// Group this entry belongs to. Entries in the same group render
    /// together.
    pub group: MenuGroup,
    /// Required role name (lowercase, snake_case). If set, the host
    /// hides this entry from users who do not have the role.
    /// `None` means the entry is visible to all authenticated users.
    pub required_role: Option<String>,
    /// Ordering within a group. Lower numbers render first. Use 100 as
    /// a neutral default so plugins can bracket entries above and below
    /// existing ones.
    pub priority: i32,
    /// Parent entry id for nested sub-items (renders as a collapsible
    /// sub-menu). `None` means the entry is a top-level item within
    /// its group.
    pub parent: Option<String>,
}

impl MenuEntry {
    /// Convenience constructor for a top-level entry.
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        url: impl Into<String>,
        group: MenuGroup,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            url: url.into(),
            icon: None,
            group,
            required_role: None,
            priority: 100,
            parent: None,
        }
    }

    pub fn with_icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    pub fn require_role(mut self, role: impl Into<String>) -> Self {
        self.required_role = Some(role.into());
        self
    }

    pub fn under(mut self, parent_id: impl Into<String>) -> Self {
        self.parent = Some(parent_id.into());
        self
    }
}

/// Top-level menu groupings. The set is intentionally small and the
/// host controls rendering order; plugins pick the closest fit rather
/// than inventing new groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MenuGroup {
    /// Top-level things (home, dashboard) that predate any module.
    Main,
    /// Operational modules (CRM, CR workflow, procurement, etc.) —
    /// the day-to-day user work.
    Operations,
    /// Reports, dashboards, KPIs.
    Reporting,
    /// Administration: users, roles, policies, modules, settings.
    Administration,
    /// Developer tooling and diagnostics (audit verify, policy test).
    Diagnostics,
}

impl MenuGroup {
    /// Stable display label for the group header.
    pub fn label(&self) -> &'static str {
        match self {
            MenuGroup::Main => "",
            MenuGroup::Operations => "Operations",
            MenuGroup::Reporting => "Reporting",
            MenuGroup::Administration => "Administration",
            MenuGroup::Diagnostics => "Diagnostics",
        }
    }

    /// Group ordering in the sidebar. Lower numbers render first.
    pub fn priority(&self) -> i32 {
        match self {
            MenuGroup::Main => 0,
            MenuGroup::Operations => 100,
            MenuGroup::Reporting => 200,
            MenuGroup::Administration => 300,
            MenuGroup::Diagnostics => 400,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_entry_builder() {
        let entry = MenuEntry::new("crm.leads", "Leads", "/crm/leads", MenuGroup::Operations)
            .with_icon("wrench")
            .with_priority(20)
            .require_role("technician");
        assert_eq!(entry.id, "crm.leads");
        assert_eq!(entry.priority, 20);
        assert_eq!(entry.required_role.as_deref(), Some("technician"));
        assert_eq!(entry.group, MenuGroup::Operations);
    }

    #[test]
    fn group_priorities_are_ordered() {
        assert!(MenuGroup::Main.priority() < MenuGroup::Operations.priority());
        assert!(MenuGroup::Operations.priority() < MenuGroup::Reporting.priority());
        assert!(MenuGroup::Reporting.priority() < MenuGroup::Administration.priority());
        assert!(MenuGroup::Administration.priority() < MenuGroup::Diagnostics.priority());
    }
}
