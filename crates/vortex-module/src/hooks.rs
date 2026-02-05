//! Hook system for module extensibility

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;
use vortex_common::VortexResult;

/// Hook execution point
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookPoint {
    // Model lifecycle hooks
    BeforeCreate,
    AfterCreate,
    BeforeUpdate,
    AfterUpdate,
    BeforeDelete,
    AfterDelete,
    BeforeRead,
    AfterRead,

    // Validation hooks
    Validate,
    ValidateCreate,
    ValidateUpdate,

    // Computed field hooks
    Compute,

    // Security hooks
    CheckAccess,
    BeforeLogin,
    AfterLogin,
    BeforeLogout,
    AfterLogout,

    // Module lifecycle
    ModuleInstall,
    ModuleUpgrade,
    ModuleUninstall,
    ModuleLoad,
    ModuleUnload,

    // Custom hook point
    Custom,
}

/// Hook priority (lower = runs first)
pub type Priority = i32;

/// A registered hook
pub struct Hook {
    /// Hook identifier
    pub id: String,
    /// Module that registered this hook
    pub module: String,
    /// Target model (or "*" for all)
    pub model: String,
    /// Hook point
    pub point: HookPoint,
    /// Priority (lower = runs first)
    pub priority: Priority,
    /// The hook function
    pub handler: Arc<dyn HookHandler>,
}

/// Hook handler trait
#[async_trait::async_trait]
pub trait HookHandler: Send + Sync {
    /// Execute the hook
    async fn execute(&self, context: &mut HookContext) -> VortexResult<()>;
}

/// Context passed to hooks
pub struct HookContext {
    /// The model being operated on
    pub model: String,
    /// The operation context
    pub operation_context: vortex_common::Context,
    /// Record data (if applicable)
    pub data: HashMap<String, serde_json::Value>,
    /// Original data (for updates)
    pub original_data: Option<HashMap<String, serde_json::Value>>,
    /// Whether to cancel the operation
    pub cancel: bool,
    /// Error message if cancelled
    pub cancel_reason: Option<String>,
    /// Additional context data
    pub extra: HashMap<String, Box<dyn Any + Send + Sync>>,
}

impl HookContext {
    /// Create a new hook context
    pub fn new(model: impl Into<String>, ctx: vortex_common::Context) -> Self {
        Self {
            model: model.into(),
            operation_context: ctx,
            data: HashMap::new(),
            original_data: None,
            cancel: false,
            cancel_reason: None,
            extra: HashMap::new(),
        }
    }

    /// Set record data
    pub fn with_data(mut self, data: HashMap<String, serde_json::Value>) -> Self {
        self.data = data;
        self
    }

    /// Set original data
    pub fn with_original(mut self, data: HashMap<String, serde_json::Value>) -> Self {
        self.original_data = Some(data);
        self
    }

    /// Cancel the operation
    pub fn cancel(&mut self, reason: impl Into<String>) {
        self.cancel = true;
        self.cancel_reason = Some(reason.into());
    }

    /// Get a value from data
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }

    /// Set a value in data
    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.data.insert(key.into(), value);
    }

    /// Store extra context data
    pub fn set_extra<T: Any + Send + Sync>(&mut self, key: impl Into<String>, value: T) {
        self.extra.insert(key.into(), Box::new(value));
    }

    /// Get extra context data
    pub fn get_extra<T: Any + Send + Sync>(&self, key: &str) -> Option<&T> {
        self.extra.get(key).and_then(|v| v.downcast_ref())
    }
}

/// Hook registry
pub struct HookRegistry {
    hooks: RwLock<Vec<Hook>>,
}

impl HookRegistry {
    /// Create a new hook registry
    pub fn new() -> Self {
        Self {
            hooks: RwLock::new(Vec::new()),
        }
    }

    /// Register a hook
    pub async fn register(&self, hook: Hook) {
        let hook_id = hook.id.clone();
        let hook_model = hook.model.clone();

        let mut hooks = self.hooks.write().await;
        hooks.push(hook);

        // Sort by priority
        hooks.sort_by_key(|h| h.priority);

        debug!("Hook registered: {} for {}", hook_id, hook_model);
    }

    /// Unregister all hooks for a module
    pub async fn unregister_module(&self, module: &str) {
        let mut hooks = self.hooks.write().await;
        hooks.retain(|h| h.module != module);
    }

    /// Execute hooks for a given point
    pub async fn execute(
        &self,
        point: HookPoint,
        model: &str,
        context: &mut HookContext,
    ) -> VortexResult<()> {
        let hooks = self.hooks.read().await;

        for hook in hooks.iter() {
            // Check if hook applies
            if hook.point != point {
                continue;
            }
            if hook.model != "*" && hook.model != model {
                continue;
            }

            // Execute hook
            debug!("Executing hook: {} for {}", hook.id, model);
            hook.handler.execute(context).await?;

            // Check if operation was cancelled
            if context.cancel {
                return Err(vortex_common::VortexError::ValidationFailed(
                    context.cancel_reason.clone().unwrap_or_else(|| "Operation cancelled by hook".to_string()),
                ));
            }
        }

        Ok(())
    }

    /// Get hooks for a point and model
    pub async fn get_hooks(&self, point: HookPoint, model: &str) -> Vec<String> {
        let hooks = self.hooks.read().await;
        hooks
            .iter()
            .filter(|h| h.point == point && (h.model == "*" || h.model == model))
            .map(|h| h.id.clone())
            .collect()
    }
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to create a simple hook handler from a closure
pub fn hook_fn<F>(f: F) -> Arc<dyn HookHandler>
where
    F: Fn(&mut HookContext) -> VortexResult<()> + Send + Sync + 'static,
{
    struct FnHook<F>(F);

    #[async_trait::async_trait]
    impl<F> HookHandler for FnHook<F>
    where
        F: Fn(&mut HookContext) -> VortexResult<()> + Send + Sync + 'static,
    {
        async fn execute(&self, context: &mut HookContext) -> VortexResult<()> {
            (self.0)(context)
        }
    }

    Arc::new(FnHook(f))
}

/// Helper to create an async hook handler
pub fn async_hook_fn<F, Fut>(f: F) -> Arc<dyn HookHandler>
where
    F: Fn(HookContext) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = VortexResult<HookContext>> + Send + 'static,
{
    struct AsyncFnHook<F>(F);

    #[async_trait::async_trait]
    impl<F, Fut> HookHandler for AsyncFnHook<F>
    where
        F: Fn(HookContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = VortexResult<HookContext>> + Send + 'static,
    {
        async fn execute(&self, context: &mut HookContext) -> VortexResult<()> {
            // This is a simplified version - in production you'd handle this better
            Ok(())
        }
    }

    Arc::new(AsyncFnHook(f))
}
