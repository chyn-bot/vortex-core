//! Module loader with dependency resolution

use crate::manifest::{ModuleManifest, ModuleState};
use petgraph::algo::toposort;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use vortex_common::{ModuleId, VortexError, VortexResult};

/// Module trait that all modules must implement
#[async_trait::async_trait]
pub trait Module: Send + Sync {
    /// Get the module manifest
    fn manifest(&self) -> &ModuleManifest;

    /// Called when the module is being installed
    async fn install(&self) -> VortexResult<()> {
        Ok(())
    }

    /// Called when the module is being upgraded
    async fn upgrade(&self, from_version: &str) -> VortexResult<()> {
        Ok(())
    }

    /// Called when the module is being uninstalled
    async fn uninstall(&self) -> VortexResult<()> {
        Ok(())
    }

    /// Called when the module is loaded (after install or on startup)
    async fn load(&self) -> VortexResult<()> {
        Ok(())
    }

    /// Called when the module is being unloaded (before uninstall or shutdown)
    async fn unload(&self) -> VortexResult<()> {
        Ok(())
    }

    /// Register the module's models with the registry
    fn register_models(&self) {}

    /// Register the module's hooks
    fn register_hooks(&self, _registry: &crate::hooks::HookRegistry) {}
}

/// Module loader responsible for managing module lifecycle
pub struct ModuleLoader {
    /// Registered modules
    modules: RwLock<HashMap<ModuleId, Arc<dyn Module>>>,
    /// Module states
    states: RwLock<HashMap<ModuleId, ModuleState>>,
    /// Dependency graph
    dep_graph: RwLock<DiGraph<ModuleId, ()>>,
    /// Node indices for dependency graph
    node_indices: RwLock<HashMap<ModuleId, NodeIndex>>,
}

impl ModuleLoader {
    /// Create a new module loader
    pub fn new() -> Self {
        Self {
            modules: RwLock::new(HashMap::new()),
            states: RwLock::new(HashMap::new()),
            dep_graph: RwLock::new(DiGraph::new()),
            node_indices: RwLock::new(HashMap::new()),
        }
    }

    /// Register a module
    pub async fn register(&self, module: Arc<dyn Module>) -> VortexResult<()> {
        let module_id = module.manifest().id.clone();
        let module_name = module.manifest().name.clone();

        // Add to modules
        {
            let mut modules = self.modules.write().await;
            if modules.contains_key(&module_id) {
                return Err(VortexError::ModuleLoadFailed {
                    module: module_id.0.clone(),
                    reason: "Module already registered".to_string(),
                });
            }
            modules.insert(module_id.clone(), module);
        }

        // Add to dependency graph
        {
            let mut graph = self.dep_graph.write().await;
            let mut indices = self.node_indices.write().await;

            let node = graph.add_node(module_id.clone());
            indices.insert(module_id.clone(), node);
        }

        // Set initial state
        {
            let mut states = self.states.write().await;
            states.insert(module_id.clone(), ModuleState::Uninstalled);
        }

        info!("Module registered: {}", module_name);
        Ok(())
    }

    /// Build dependency edges in the graph
    pub async fn build_dependency_graph(&self) -> VortexResult<()> {
        let modules = self.modules.read().await;
        let mut graph = self.dep_graph.write().await;
        let indices = self.node_indices.read().await;

        for (module_id, module) in modules.iter() {
            let manifest = module.manifest();
            let module_node = indices.get(module_id).ok_or_else(|| {
                VortexError::ModuleLoadFailed {
                    module: module_id.0.clone(),
                    reason: "Module node not found".to_string(),
                }
            })?;

            for dep in &manifest.dependencies {
                if dep.optional && !modules.contains_key(&dep.module_id) {
                    continue;
                }

                let dep_node = indices.get(&dep.module_id).ok_or_else(|| {
                    VortexError::ModuleDependencyError {
                        module: module_id.0.clone(),
                        dependency: dep.module_id.0.clone(),
                    }
                })?;

                // Edge from dependency to dependent (for topological sort)
                graph.add_edge(*dep_node, *module_node, ());
            }
        }

        // Check for cycles
        if toposort(&*graph, None).is_err() {
            return Err(VortexError::CircularDependency(
                "Circular dependency detected in modules".to_string(),
            ));
        }

        debug!("Dependency graph built successfully");
        Ok(())
    }

    /// Get load order for modules (topologically sorted)
    pub async fn get_load_order(&self) -> VortexResult<Vec<ModuleId>> {
        let graph = self.dep_graph.read().await;

        let sorted = toposort(&*graph, None).map_err(|_| {
            VortexError::CircularDependency("Circular dependency detected".to_string())
        })?;

        Ok(sorted.into_iter().map(|n| graph[n].clone()).collect())
    }

    /// Install a module and its dependencies
    pub async fn install(&self, module_id: &ModuleId) -> VortexResult<()> {
        // Get dependencies in order
        let load_order = self.get_install_order(module_id).await?;

        for id in load_order {
            self.install_single(&id).await?;
        }

        Ok(())
    }

    /// Get installation order for a module (including dependencies)
    async fn get_install_order(&self, module_id: &ModuleId) -> VortexResult<Vec<ModuleId>> {
        let modules = self.modules.read().await;
        let states = self.states.read().await;

        let mut order = Vec::new();
        let mut visited = std::collections::HashSet::new();

        self.collect_dependencies(module_id, &modules, &states, &mut order, &mut visited)?;

        Ok(order)
    }

    /// Recursively collect dependencies
    fn collect_dependencies(
        &self,
        module_id: &ModuleId,
        modules: &HashMap<ModuleId, Arc<dyn Module>>,
        states: &HashMap<ModuleId, ModuleState>,
        order: &mut Vec<ModuleId>,
        visited: &mut std::collections::HashSet<ModuleId>,
    ) -> VortexResult<()> {
        if visited.contains(module_id) {
            return Ok(());
        }
        visited.insert(module_id.clone());

        let module = modules.get(module_id).ok_or_else(|| {
            VortexError::ModuleNotFound(module_id.0.clone())
        })?;

        // Process dependencies first
        for dep in &module.manifest().dependencies {
            if !dep.optional || modules.contains_key(&dep.module_id) {
                self.collect_dependencies(&dep.module_id, modules, states, order, visited)?;
            }
        }

        // Add this module if not already installed
        if states.get(module_id) != Some(&ModuleState::Installed) {
            order.push(module_id.clone());
        }

        Ok(())
    }

    /// Install a single module (assumes dependencies are installed)
    async fn install_single(&self, module_id: &ModuleId) -> VortexResult<()> {
        let module = {
            let modules = self.modules.read().await;
            modules.get(module_id).cloned().ok_or_else(|| {
                VortexError::ModuleNotFound(module_id.0.clone())
            })?
        };

        // Update state to installing
        {
            let mut states = self.states.write().await;
            states.insert(module_id.clone(), ModuleState::Installing);
        }

        info!("Installing module: {}", module.manifest().name);

        // Run installation
        match module.install().await {
            Ok(_) => {
                // Register models
                module.register_models();

                // Load module
                module.load().await?;

                // Update state
                let mut states = self.states.write().await;
                states.insert(module_id.clone(), ModuleState::Installed);

                info!("Module installed: {}", module.manifest().name);
                Ok(())
            }
            Err(e) => {
                // Update state to failed
                let mut states = self.states.write().await;
                states.insert(module_id.clone(), ModuleState::Failed);

                error!("Module installation failed: {} - {}", module.manifest().name, e);
                Err(e)
            }
        }
    }

    /// Uninstall a module
    pub async fn uninstall(&self, module_id: &ModuleId) -> VortexResult<()> {
        // Check if any installed module depends on this one
        {
            let modules = self.modules.read().await;
            let states = self.states.read().await;

            for (id, module) in modules.iter() {
                if id == module_id {
                    continue;
                }

                if states.get(id) != Some(&ModuleState::Installed) {
                    continue;
                }

                for dep in &module.manifest().dependencies {
                    if &dep.module_id == module_id && !dep.optional {
                        return Err(VortexError::ModuleDependencyError {
                            module: id.0.clone(),
                            dependency: module_id.0.clone(),
                        });
                    }
                }
            }
        }

        let module = {
            let modules = self.modules.read().await;
            modules.get(module_id).cloned().ok_or_else(|| {
                VortexError::ModuleNotFound(module_id.0.clone())
            })?
        };

        // Check if removable
        if !module.manifest().removable {
            return Err(VortexError::SecurityPolicyViolation(
                "Cannot uninstall core module".to_string(),
            ));
        }

        // Update state
        {
            let mut states = self.states.write().await;
            states.insert(module_id.clone(), ModuleState::Uninstalling);
        }

        info!("Uninstalling module: {}", module.manifest().name);

        // Unload and uninstall
        module.unload().await?;
        module.uninstall().await?;

        // Update state
        {
            let mut states = self.states.write().await;
            states.insert(module_id.clone(), ModuleState::Uninstalled);
        }

        info!("Module uninstalled: {}", module.manifest().name);
        Ok(())
    }

    /// Get a module by ID
    pub async fn get(&self, module_id: &ModuleId) -> Option<Arc<dyn Module>> {
        let modules = self.modules.read().await;
        modules.get(module_id).cloned()
    }

    /// Get module state
    pub async fn get_state(&self, module_id: &ModuleId) -> Option<ModuleState> {
        let states = self.states.read().await;
        states.get(module_id).copied()
    }

    /// Get all installed modules
    pub async fn get_installed(&self) -> Vec<Arc<dyn Module>> {
        let modules = self.modules.read().await;
        let states = self.states.read().await;

        modules
            .iter()
            .filter(|(id, _)| states.get(*id) == Some(&ModuleState::Installed))
            .map(|(_, m)| m.clone())
            .collect()
    }
}

impl Default for ModuleLoader {
    fn default() -> Self {
        Self::new()
    }
}
