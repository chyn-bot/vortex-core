//! Vortex Module System
//!
//! Provides a modular architecture for extending Vortex with:
//! - Dependency resolution and load ordering
//! - Model inheritance and extension
//! - Hook system for overrides
//! - Database migration management
//! - Per-database module installation (Odoo-style)

pub mod manifest;
pub mod loader;
pub mod hooks;
pub mod inheritance;
pub mod repository;

pub mod prelude {
    pub use crate::manifest::{ModuleManifest, ModuleState};
    pub use crate::loader::ModuleLoader;
    pub use crate::hooks::{Hook, HookRegistry, HookPoint};
    pub use crate::inheritance::{ModelExtension, InheritanceType};
    pub use crate::repository::{ModuleRepository, InstalledModule, DbModuleState};
}

pub use prelude::*;
