//! Module manifest definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_common::ModuleId;

/// Module manifest describing a Vortex module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleManifest {
    /// Unique module identifier
    pub id: ModuleId,
    /// Human-readable name
    pub name: String,
    /// Module version (semver)
    pub version: String,
    /// Module description
    pub description: Option<String>,
    /// Author information
    pub author: Option<String>,
    /// License
    pub license: Option<String>,
    /// Website/repository URL
    pub website: Option<String>,
    /// Module category
    pub category: ModuleCategory,
    /// Dependencies on other modules
    pub dependencies: Vec<ModuleDependency>,
    /// Modules this module conflicts with
    pub conflicts: Vec<ModuleId>,
    /// Whether this is a core module
    pub is_core: bool,
    /// Whether this module can be uninstalled
    pub removable: bool,
    /// Auto-install flag
    pub auto_install: bool,
    /// Module state
    pub state: ModuleState,
    /// Installation timestamp
    pub installed_at: Option<DateTime<Utc>>,
    /// Last update timestamp
    pub updated_at: Option<DateTime<Utc>>,
    /// Models provided by this module
    pub models: Vec<String>,
    /// Migrations provided by this module
    pub migrations: Vec<String>,
}

impl ModuleManifest {
    /// Create a new module manifest
    pub fn new(id: impl Into<String>, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: ModuleId::new(id),
            name: name.into(),
            version: version.into(),
            description: None,
            author: None,
            license: None,
            website: None,
            category: ModuleCategory::Uncategorized,
            dependencies: Vec::new(),
            conflicts: Vec::new(),
            is_core: false,
            removable: true,
            auto_install: false,
            state: ModuleState::Uninstalled,
            installed_at: None,
            updated_at: None,
            models: Vec::new(),
            migrations: Vec::new(),
        }
    }

    /// Mark as core module
    pub fn core(mut self) -> Self {
        self.is_core = true;
        self.removable = false;
        self
    }

    /// Add dependency
    pub fn depends_on(mut self, module: impl Into<String>, version: impl Into<String>) -> Self {
        self.dependencies.push(ModuleDependency {
            module_id: ModuleId::new(module),
            version_constraint: version.into(),
            optional: false,
        });
        self
    }

    /// Add optional dependency
    pub fn optionally_depends_on(mut self, module: impl Into<String>, version: impl Into<String>) -> Self {
        self.dependencies.push(ModuleDependency {
            module_id: ModuleId::new(module),
            version_constraint: version.into(),
            optional: true,
        });
        self
    }

    /// Add model
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.models.push(model.into());
        self
    }

    /// Add migration
    pub fn with_migration(mut self, migration: impl Into<String>) -> Self {
        self.migrations.push(migration.into());
        self
    }
}

/// Module dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleDependency {
    /// Module ID
    pub module_id: ModuleId,
    /// Version constraint (semver)
    pub version_constraint: String,
    /// Whether this dependency is optional
    pub optional: bool,
}

/// Module categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ModuleCategory {
    #[default]
    Uncategorized,
    Core,
    Accounting,
    Sales,
    Purchase,
    Inventory,
    Manufacturing,
    HR,
    Project,
    CRM,
    Website,
    Integration,
    Reporting,
    Security,
    Utility,
}

/// Module state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    #[default]
    Uninstalled,
    Installing,
    Installed,
    Upgrading,
    Uninstalling,
    Failed,
    Disabled,
}

impl ModuleState {
    pub fn is_active(&self) -> bool {
        matches!(self, ModuleState::Installed)
    }

    pub fn is_transitioning(&self) -> bool {
        matches!(
            self,
            ModuleState::Installing | ModuleState::Upgrading | ModuleState::Uninstalling
        )
    }
}
