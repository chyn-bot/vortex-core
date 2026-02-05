//! Model registry for dynamic model access

use crate::model::ModelMeta;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;

/// Global model registry
pub struct ModelRegistry {
    models: RwLock<HashMap<String, Arc<ModelMeta>>>,
    type_ids: RwLock<HashMap<TypeId, String>>,
}

impl ModelRegistry {
    /// Create a new model registry
    pub fn new() -> Self {
        Self {
            models: RwLock::new(HashMap::new()),
            type_ids: RwLock::new(HashMap::new()),
        }
    }

    /// Register a model
    pub fn register<M: crate::model::Model>(&self) {
        let meta = M::meta();
        let name = meta.name.clone();
        let type_id = TypeId::of::<M>();

        {
            let mut models = self.models.write().unwrap();
            models.insert(name.clone(), Arc::new(meta.clone()));
        }

        {
            let mut type_ids = self.type_ids.write().unwrap();
            type_ids.insert(type_id, name.clone());
        }

        info!("Registered model: {}", name);
    }

    /// Get model metadata by name
    pub fn get(&self, name: &str) -> Option<Arc<ModelMeta>> {
        let models = self.models.read().unwrap();
        models.get(name).cloned()
    }

    /// Get model name by type
    pub fn get_name<M: 'static>(&self) -> Option<String> {
        let type_ids = self.type_ids.read().unwrap();
        type_ids.get(&TypeId::of::<M>()).cloned()
    }

    /// Get all registered models
    pub fn all(&self) -> Vec<Arc<ModelMeta>> {
        let models = self.models.read().unwrap();
        models.values().cloned().collect()
    }

    /// Get models by module
    pub fn by_module(&self, module: &str) -> Vec<Arc<ModelMeta>> {
        let models = self.models.read().unwrap();
        models
            .values()
            .filter(|m| m.module == module)
            .cloned()
            .collect()
    }

    /// Check if a model is registered
    pub fn contains(&self, name: &str) -> bool {
        let models = self.models.read().unwrap();
        models.contains_key(name)
    }

    /// Get table name for a model
    pub fn table_name(&self, model_name: &str) -> Option<String> {
        self.get(model_name).map(|m| m.table.clone())
    }
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global registry instance
static REGISTRY: std::sync::OnceLock<ModelRegistry> = std::sync::OnceLock::new();

/// Get the global model registry
pub fn registry() -> &'static ModelRegistry {
    REGISTRY.get_or_init(ModelRegistry::new)
}

/// Register a model with the global registry
pub fn register<M: crate::model::Model>() {
    registry().register::<M>();
}
