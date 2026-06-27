//! Access Controller Service
//!
//! Central service coordinating all access control checks. Implements the
//! three-tier access control model (model access, record rules, field access)
//! with caching for performance.
//!
//! # Compliance
//!
//! - Access management and authorization
//! - Audit logging of access denials

use crate::domain::{DomainExpr, DomainValue, PostgresDialect, SqlDialect};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};
use uuid::Uuid;
use vortex_common::{CompanyId, Context, FieldValue, UserId, VortexError, VortexResult};

/// Access mode for checking permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessMode {
    Read,
    Write,
    Create,
    Delete,
}

impl AccessMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AccessMode::Read => "read",
            AccessMode::Write => "write",
            AccessMode::Create => "create",
            AccessMode::Delete => "delete",
        }
    }
}

impl std::fmt::Display for AccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Model access rule from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAccessRule {
    pub id: Uuid,
    pub model_name: String,
    pub role_id: Uuid,
    pub perm_read: bool,
    pub perm_write: bool,
    pub perm_create: bool,
    pub perm_delete: bool,
    pub company_id: Option<CompanyId>,
    pub active: bool,
}

impl ModelAccessRule {
    /// Check if this rule grants the specified permission
    pub fn allows(&self, mode: AccessMode) -> bool {
        match mode {
            AccessMode::Read => self.perm_read,
            AccessMode::Write => self.perm_write,
            AccessMode::Create => self.perm_create,
            AccessMode::Delete => self.perm_delete,
        }
    }
}

/// Record rule from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordRuleEntry {
    pub id: Uuid,
    pub name: String,
    pub model_name: String,
    pub domain_expression: String,
    pub role_id: Option<Uuid>,
    pub perm_read: bool,
    pub perm_write: bool,
    pub perm_create: bool,
    pub perm_delete: bool,
    pub is_global: bool,
    pub priority: i32,
    pub active: bool,
    pub company_id: Option<CompanyId>,
}

impl RecordRuleEntry {
    /// Check if this rule applies to the given mode
    pub fn applies_to_mode(&self, mode: AccessMode) -> bool {
        match mode {
            AccessMode::Read => self.perm_read,
            AccessMode::Write => self.perm_write,
            AccessMode::Create => self.perm_create,
            AccessMode::Delete => self.perm_delete,
        }
    }

    /// Parse the domain expression
    pub fn parse_domain(&self) -> VortexResult<DomainExpr> {
        DomainExpr::parse(&self.domain_expression)
    }
}

/// Field access rule from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAccessRule {
    pub id: Uuid,
    pub model_name: String,
    pub field_name: String,
    pub role_id: Uuid,
    pub readable: bool,
    pub writable: bool,
    pub company_id: Option<CompanyId>,
    pub active: bool,
}

/// Map of field names to their access permissions
#[derive(Debug, Clone, Default)]
pub struct FieldAccessMap {
    /// Fields with explicit readable=true
    pub readable: Vec<String>,
    /// Fields with explicit writable=true
    pub writable: Vec<String>,
    /// Fields that are explicitly hidden (readable=false)
    pub hidden: Vec<String>,
    /// Fields that are read-only (writable=false)
    pub readonly: Vec<String>,
}

impl FieldAccessMap {
    /// Check if a field is readable
    pub fn can_read(&self, field: &str) -> bool {
        !self.hidden.contains(&field.to_string())
    }

    /// Check if a field is writable
    pub fn can_write(&self, field: &str) -> bool {
        !self.hidden.contains(&field.to_string()) && !self.readonly.contains(&field.to_string())
    }

    /// Filter a record to only include readable fields
    pub fn filter_readable<V: Clone>(&self, record: &HashMap<String, V>) -> HashMap<String, V> {
        record
            .iter()
            .filter(|(k, _)| self.can_read(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Filter values to only include writable fields
    pub fn filter_writable<V: Clone>(&self, values: &HashMap<String, V>) -> HashMap<String, V> {
        values
            .iter()
            .filter(|(k, _)| self.can_write(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Cache entry with expiration
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
}

impl<T> CacheEntry<T> {
    fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Cache key for model access
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ModelAccessKey {
    role_ids: Vec<Uuid>,
    model_name: String,
    mode: AccessMode,
    company_id: Option<Uuid>,
}

/// Cache key for record domains
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RecordDomainKey {
    role_ids: Vec<Uuid>,
    model_name: String,
    mode: AccessMode,
    company_id: Option<Uuid>,
}

/// Access cache for performance
struct AccessCache {
    /// Model access cache: (roles, model, mode) -> allowed
    model_access: RwLock<HashMap<ModelAccessKey, CacheEntry<bool>>>,
    /// Record domain cache: (roles, model, mode) -> domain expression
    record_domains: RwLock<HashMap<RecordDomainKey, CacheEntry<Option<DomainExpr>>>>,
    /// Field access cache: (roles, model) -> field map
    field_access: RwLock<HashMap<(Vec<Uuid>, String), CacheEntry<FieldAccessMap>>>,
    /// Cache TTL
    ttl: Duration,
}

impl AccessCache {
    fn new(ttl: Duration) -> Self {
        Self {
            model_access: RwLock::new(HashMap::new()),
            record_domains: RwLock::new(HashMap::new()),
            field_access: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    async fn get_model_access(&self, key: &ModelAccessKey) -> Option<bool> {
        let cache = self.model_access.read().await;
        cache.get(key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.value)
            }
        })
    }

    async fn set_model_access(&self, key: ModelAccessKey, value: bool) {
        let mut cache = self.model_access.write().await;
        cache.insert(key, CacheEntry::new(value, self.ttl));
    }

    async fn get_record_domain(&self, key: &RecordDomainKey) -> Option<Option<DomainExpr>> {
        let cache = self.record_domains.read().await;
        cache.get(key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.value.clone())
            }
        })
    }

    async fn set_record_domain(&self, key: RecordDomainKey, value: Option<DomainExpr>) {
        let mut cache = self.record_domains.write().await;
        cache.insert(key, CacheEntry::new(value, self.ttl));
    }

    async fn get_field_access(&self, role_ids: &[Uuid], model: &str) -> Option<FieldAccessMap> {
        let cache = self.field_access.read().await;
        let key = (role_ids.to_vec(), model.to_string());
        cache.get(&key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.value.clone())
            }
        })
    }

    async fn set_field_access(&self, role_ids: Vec<Uuid>, model: String, value: FieldAccessMap) {
        let mut cache = self.field_access.write().await;
        cache.insert((role_ids, model), CacheEntry::new(value, self.ttl));
    }

    /// Clear all caches
    async fn clear(&self) {
        self.model_access.write().await.clear();
        self.record_domains.write().await.clear();
        self.field_access.write().await.clear();
    }
}

/// Access control data store trait
///
/// Implement this trait to provide database access for the controller.
#[async_trait::async_trait]
pub trait AccessStore: Send + Sync {
    /// Load model access rules for the given roles and model
    async fn load_model_access(
        &self,
        role_ids: &[Uuid],
        model_name: &str,
        company_id: Option<CompanyId>,
    ) -> VortexResult<Vec<ModelAccessRule>>;

    /// Load record rules for the given roles and model
    async fn load_record_rules(
        &self,
        role_ids: &[Uuid],
        model_name: &str,
        company_id: Option<CompanyId>,
    ) -> VortexResult<Vec<RecordRuleEntry>>;

    /// Load field access rules for the given roles and model
    async fn load_field_access(
        &self,
        role_ids: &[Uuid],
        model_name: &str,
        company_id: Option<CompanyId>,
    ) -> VortexResult<Vec<FieldAccessRule>>;

    /// Get role IDs for a user
    async fn get_user_role_ids(&self, user_id: UserId) -> VortexResult<Vec<Uuid>>;
}

/// Central access control service
pub struct AccessController<S: AccessStore> {
    store: Arc<S>,
    cache: AccessCache,
    /// Whether to allow access when no rules are defined (default: false)
    allow_without_rules: bool,
}

impl<S: AccessStore> AccessController<S> {
    /// Create a new access controller
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            cache: AccessCache::new(Duration::from_secs(300)), // 5 minute cache
            allow_without_rules: false,
        }
    }

    /// Create with custom cache TTL
    pub fn with_cache_ttl(store: Arc<S>, ttl: Duration) -> Self {
        Self {
            store,
            cache: AccessCache::new(ttl),
            allow_without_rules: false,
        }
    }

    /// Set whether to allow access when no rules are defined
    pub fn set_allow_without_rules(&mut self, allow: bool) {
        self.allow_without_rules = allow;
    }

    /// Clear all caches
    pub async fn clear_cache(&self) {
        self.cache.clear().await;
    }

    /// Get role IDs for the context
    async fn get_role_ids(&self, ctx: &Context) -> VortexResult<Vec<Uuid>> {
        if let Some(user_id) = ctx.user_id {
            self.store.get_user_role_ids(user_id).await
        } else {
            Ok(Vec::new())
        }
    }

    /// Check model-level access (Phase 1 of access check)
    ///
    /// Returns Ok(()) if access is allowed, or an AccessDenied error.
    pub async fn check_model_access(
        &self,
        ctx: &Context,
        model: &str,
        mode: AccessMode,
    ) -> VortexResult<()> {
        // System context bypasses all checks
        if ctx.is_system {
            debug!("Model access granted (system context): {} {}", mode, model);
            return Ok(());
        }

        let role_ids = self.get_role_ids(ctx).await?;

        // Check cache first
        let cache_key = ModelAccessKey {
            role_ids: role_ids.clone(),
            model_name: model.to_string(),
            mode,
            company_id: ctx.company_id.map(|c| c.0),
        };

        if let Some(allowed) = self.cache.get_model_access(&cache_key).await {
            if allowed {
                return Ok(());
            } else {
                return Err(VortexError::AccessDenied {
                    action: mode.to_string(),
                    resource: model.to_string(),
                });
            }
        }

        // Load from database
        let rules = self
            .store
            .load_model_access(&role_ids, model, ctx.company_id)
            .await?;

        // Check if any rule grants the permission
        let allowed = if rules.is_empty() {
            self.allow_without_rules
        } else {
            rules.iter().any(|r| r.active && r.allows(mode))
        };

        // Cache the result
        self.cache.set_model_access(cache_key, allowed).await;

        if allowed {
            debug!("Model access granted: {} {} for {:?}", mode, model, role_ids);
            Ok(())
        } else {
            warn!(
                "Model access denied: {} {} for {:?}",
                mode, model, role_ids
            );
            Err(VortexError::AccessDenied {
                action: mode.to_string(),
                resource: model.to_string(),
            })
        }
    }

    /// Get domain filter for record-level access (Phase 2)
    ///
    /// Returns a domain expression that should be applied to queries,
    /// or None if no filtering is required.
    pub async fn get_record_domain(
        &self,
        ctx: &Context,
        model: &str,
        mode: AccessMode,
    ) -> VortexResult<Option<DomainExpr>> {
        // System context bypasses all checks
        if ctx.is_system {
            return Ok(None);
        }

        let role_ids = self.get_role_ids(ctx).await?;

        // Check cache first
        let cache_key = RecordDomainKey {
            role_ids: role_ids.clone(),
            model_name: model.to_string(),
            mode,
            company_id: ctx.company_id.map(|c| c.0),
        };

        if let Some(cached) = self.cache.get_record_domain(&cache_key).await {
            return Ok(cached);
        }

        // Load from database
        let rules = self
            .store
            .load_record_rules(&role_ids, model, ctx.company_id)
            .await?;

        // Collect applicable rules
        let mut applicable_rules: Vec<_> = rules
            .into_iter()
            .filter(|r| r.active && r.applies_to_mode(mode))
            .collect();

        // Sort by priority (higher first)
        applicable_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        if applicable_rules.is_empty() {
            self.cache.set_record_domain(cache_key, None).await;
            return Ok(None);
        }

        // Combine rules:
        // - Global rules are ANDed together (all must pass)
        // - Role-specific rules are ORed together (any can pass)
        // - Final result: global AND role_specific

        let mut global_domains = Vec::new();
        let mut role_domains = Vec::new();

        for rule in applicable_rules {
            match rule.parse_domain() {
                Ok(domain) => {
                    if rule.is_global {
                        global_domains.push(domain);
                    } else {
                        role_domains.push(domain);
                    }
                }
                Err(e) => {
                    warn!("Failed to parse domain for rule '{}': {}", rule.name, e);
                }
            }
        }

        let result = match (global_domains.is_empty(), role_domains.is_empty()) {
            (true, true) => None,
            (false, true) => Some(DomainExpr::and(global_domains)),
            (true, false) => Some(DomainExpr::or(role_domains)),
            (false, false) => {
                let global = DomainExpr::and(global_domains);
                let role = DomainExpr::or(role_domains);
                Some(DomainExpr::and(vec![global, role]))
            }
        };

        self.cache.set_record_domain(cache_key, result.clone()).await;
        Ok(result)
    }

    /// Get field-level access permissions (Phase 3)
    pub async fn get_field_access(
        &self,
        ctx: &Context,
        model: &str,
    ) -> VortexResult<FieldAccessMap> {
        // System context has full access
        if ctx.is_system {
            return Ok(FieldAccessMap::default());
        }

        let role_ids = self.get_role_ids(ctx).await?;

        // Check cache first
        if let Some(cached) = self.cache.get_field_access(&role_ids, model).await {
            return Ok(cached);
        }

        // Load from database
        let rules = self
            .store
            .load_field_access(&role_ids, model, ctx.company_id)
            .await?;

        let mut field_map = FieldAccessMap::default();

        for rule in rules {
            if !rule.active {
                continue;
            }

            if rule.readable {
                field_map.readable.push(rule.field_name.clone());
            } else {
                field_map.hidden.push(rule.field_name.clone());
            }

            if !rule.writable && rule.readable {
                field_map.readonly.push(rule.field_name.clone());
            }
        }

        self.cache
            .set_field_access(role_ids, model.to_string(), field_map.clone())
            .await;

        Ok(field_map)
    }

    /// Combined check for a specific record
    ///
    /// Checks model access, then evaluates record rules against the record.
    pub async fn check_record_access(
        &self,
        ctx: &Context,
        model: &str,
        record: &HashMap<String, FieldValue>,
        mode: AccessMode,
    ) -> VortexResult<()> {
        // Check model access first
        self.check_model_access(ctx, model, mode).await?;

        // Get record domain and evaluate
        if let Some(domain) = self.get_record_domain(ctx, model, mode).await? {
            if !domain.evaluate(ctx, record) {
                warn!(
                    "Record access denied by domain rule: {} {} for user {:?}",
                    mode, model, ctx.user_id
                );
                return Err(VortexError::AccessDenied {
                    action: mode.to_string(),
                    resource: model.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Get SQL domain filter for queries
    ///
    /// Returns a tuple of (SQL WHERE clause, parameters) or None if no filter.
    pub async fn get_sql_domain_filter(
        &self,
        ctx: &Context,
        model: &str,
        mode: AccessMode,
        dialect: &dyn SqlDialect,
        param_idx: &mut i32,
    ) -> VortexResult<Option<(String, Vec<FieldValue>)>> {
        let domain = self.get_record_domain(ctx, model, mode).await?;

        match domain {
            Some(expr) => {
                let (sql, params) = expr.to_sql(ctx, dialect, param_idx);
                Ok(Some((sql, params)))
            }
            None => Ok(None),
        }
    }
}

/// In-memory implementation of AccessStore for testing
pub struct MemoryAccessStore {
    model_access: RwLock<Vec<ModelAccessRule>>,
    record_rules: RwLock<Vec<RecordRuleEntry>>,
    field_access: RwLock<Vec<FieldAccessRule>>,
    user_roles: RwLock<HashMap<UserId, Vec<Uuid>>>,
}

impl MemoryAccessStore {
    pub fn new() -> Self {
        Self {
            model_access: RwLock::new(Vec::new()),
            record_rules: RwLock::new(Vec::new()),
            field_access: RwLock::new(Vec::new()),
            user_roles: RwLock::new(HashMap::new()),
        }
    }

    pub async fn add_model_access(&self, rule: ModelAccessRule) {
        self.model_access.write().await.push(rule);
    }

    pub async fn add_record_rule(&self, rule: RecordRuleEntry) {
        self.record_rules.write().await.push(rule);
    }

    pub async fn add_field_access(&self, rule: FieldAccessRule) {
        self.field_access.write().await.push(rule);
    }

    pub async fn assign_role(&self, user_id: UserId, role_id: Uuid) {
        self.user_roles
            .write()
            .await
            .entry(user_id)
            .or_default()
            .push(role_id);
    }
}

impl Default for MemoryAccessStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AccessStore for MemoryAccessStore {
    async fn load_model_access(
        &self,
        role_ids: &[Uuid],
        model_name: &str,
        company_id: Option<CompanyId>,
    ) -> VortexResult<Vec<ModelAccessRule>> {
        let rules = self.model_access.read().await;
        Ok(rules
            .iter()
            .filter(|r| {
                role_ids.contains(&r.role_id)
                    && r.model_name == model_name
                    && (r.company_id.is_none() || r.company_id == company_id)
            })
            .cloned()
            .collect())
    }

    async fn load_record_rules(
        &self,
        role_ids: &[Uuid],
        model_name: &str,
        company_id: Option<CompanyId>,
    ) -> VortexResult<Vec<RecordRuleEntry>> {
        let rules = self.record_rules.read().await;
        Ok(rules
            .iter()
            .filter(|r| {
                r.model_name == model_name
                    && (r.company_id.is_none() || r.company_id == company_id)
                    && (r.is_global || r.role_id.is_none() || role_ids.contains(&r.role_id.unwrap()))
            })
            .cloned()
            .collect())
    }

    async fn load_field_access(
        &self,
        role_ids: &[Uuid],
        model_name: &str,
        company_id: Option<CompanyId>,
    ) -> VortexResult<Vec<FieldAccessRule>> {
        let rules = self.field_access.read().await;
        Ok(rules
            .iter()
            .filter(|r| {
                role_ids.contains(&r.role_id)
                    && r.model_name == model_name
                    && (r.company_id.is_none() || r.company_id == company_id)
            })
            .cloned()
            .collect())
    }

    async fn get_user_role_ids(&self, user_id: UserId) -> VortexResult<Vec<Uuid>> {
        let roles = self.user_roles.read().await;
        Ok(roles.get(&user_id).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> Context {
        Context::authenticated(
            UserId(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()),
            CompanyId(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap()),
        )
    }

    fn admin_role_id() -> Uuid {
        Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap()
    }

    fn viewer_role_id() -> Uuid {
        Uuid::parse_str("00000000-0000-0000-0000-000000000020").unwrap()
    }

    #[tokio::test]
    async fn test_model_access_allowed() {
        let store = Arc::new(MemoryAccessStore::new());
        let controller = AccessController::new(store.clone());

        let ctx = test_context();
        let user_id = ctx.user_id.unwrap();

        // Setup: assign role and create access rule
        store.assign_role(user_id, admin_role_id()).await;
        store
            .add_model_access(ModelAccessRule {
                id: Uuid::new_v4(),
                model_name: "users".to_string(),
                role_id: admin_role_id(),
                perm_read: true,
                perm_write: true,
                perm_create: true,
                perm_delete: false,
                company_id: None,
                active: true,
            })
            .await;

        // Test: read should be allowed
        let result = controller.check_model_access(&ctx, "users", AccessMode::Read).await;
        assert!(result.is_ok());

        // Test: delete should be denied
        let result = controller.check_model_access(&ctx, "users", AccessMode::Delete).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_system_context_bypasses() {
        let store = Arc::new(MemoryAccessStore::new());
        let controller = AccessController::new(store);

        let ctx = Context::system();

        // System context should always pass
        let result = controller.check_model_access(&ctx, "anything", AccessMode::Delete).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_record_domain_filter() {
        let store = Arc::new(MemoryAccessStore::new());
        let controller = AccessController::new(store.clone());

        let ctx = test_context();
        let user_id = ctx.user_id.unwrap();

        // Setup
        store.assign_role(user_id, viewer_role_id()).await;
        store
            .add_record_rule(RecordRuleEntry {
                id: Uuid::new_v4(),
                name: "multi_tenant".to_string(),
                model_name: "users".to_string(),
                domain_expression: r#"[("company_id", "=", current_company)]"#.to_string(),
                role_id: None,
                perm_read: true,
                perm_write: true,
                perm_create: true,
                perm_delete: true,
                is_global: true,
                priority: 100,
                active: true,
                company_id: None,
            })
            .await;

        // Test: should return a domain filter
        let domain = controller.get_record_domain(&ctx, "users", AccessMode::Read).await.unwrap();
        assert!(domain.is_some());

        // Verify the domain SQL
        let dialect = PostgresDialect;
        let (sql, params) = domain.unwrap().to_sql(&ctx, &dialect, &mut 1);
        assert!(sql.contains("company_id"));
        assert_eq!(params.len(), 1);
    }

    #[tokio::test]
    async fn test_field_access() {
        let store = Arc::new(MemoryAccessStore::new());
        let controller = AccessController::new(store.clone());

        let ctx = test_context();
        let user_id = ctx.user_id.unwrap();

        // Setup
        store.assign_role(user_id, viewer_role_id()).await;
        store
            .add_field_access(FieldAccessRule {
                id: Uuid::new_v4(),
                model_name: "users".to_string(),
                field_name: "password_hash".to_string(),
                role_id: viewer_role_id(),
                readable: false,
                writable: false,
                company_id: None,
                active: true,
            })
            .await;

        // Test: password_hash should be hidden
        let field_map = controller.get_field_access(&ctx, "users").await.unwrap();
        assert!(!field_map.can_read("password_hash"));
        assert!(!field_map.can_write("password_hash"));
    }

    #[tokio::test]
    async fn test_record_evaluation() {
        let store = Arc::new(MemoryAccessStore::new());
        let controller = AccessController::new(store.clone());

        let ctx = test_context();
        let user_id = ctx.user_id.unwrap();
        let company_id = ctx.company_id.unwrap();

        // Setup: model access and record rule
        store.assign_role(user_id, viewer_role_id()).await;
        store
            .add_model_access(ModelAccessRule {
                id: Uuid::new_v4(),
                model_name: "users".to_string(),
                role_id: viewer_role_id(),
                perm_read: true,
                perm_write: false,
                perm_create: false,
                perm_delete: false,
                company_id: None,
                active: true,
            })
            .await;
        store
            .add_record_rule(RecordRuleEntry {
                id: Uuid::new_v4(),
                name: "multi_tenant".to_string(),
                model_name: "users".to_string(),
                domain_expression: r#"[("company_id", "=", current_company)]"#.to_string(),
                role_id: None,
                perm_read: true,
                perm_write: true,
                perm_create: true,
                perm_delete: true,
                is_global: true,
                priority: 100,
                active: true,
                company_id: None,
            })
            .await;

        // Test: record with matching company should pass
        let mut record = HashMap::new();
        record.insert("company_id".to_string(), FieldValue::Uuid(company_id.0));

        let result = controller
            .check_record_access(&ctx, "users", &record, AccessMode::Read)
            .await;
        assert!(result.is_ok());

        // Test: record with different company should fail
        let mut other_record = HashMap::new();
        other_record.insert(
            "company_id".to_string(),
            FieldValue::Uuid(Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap()),
        );

        let result = controller
            .check_record_access(&ctx, "users", &other_record, AccessMode::Read)
            .await;
        assert!(result.is_err());
    }
}
