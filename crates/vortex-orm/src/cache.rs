//! Record caching with intelligent invalidation

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, trace};
use vortex_common::FieldValue;

/// Cache entry with metadata
#[derive(Clone)]
struct CacheEntry<V> {
    value: V,
    created_at: Instant,
    accessed_at: Instant,
    hits: u64,
}

impl<V: Clone> CacheEntry<V> {
    fn new(value: V) -> Self {
        let now = Instant::now();
        Self {
            value,
            created_at: now,
            accessed_at: now,
            hits: 0,
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }

    fn touch(&mut self) {
        self.accessed_at = Instant::now();
        self.hits += 1;
    }
}

/// Cache key for records
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordKey {
    pub model: String,
    pub pk: String,
    pub company_id: Option<String>,
}

impl RecordKey {
    pub fn new(model: impl Into<String>, pk: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            pk: pk.into(),
            company_id: None,
        }
    }

    pub fn with_company(mut self, company_id: impl Into<String>) -> Self {
        self.company_id = Some(company_id.into());
        self
    }
}

/// Record cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries
    pub max_entries: usize,
    /// Time-to-live for entries
    pub ttl: Duration,
    /// Cleanup interval
    pub cleanup_interval: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            ttl: Duration::from_secs(300), // 5 minutes
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// Record cache for ORM
pub struct RecordCache {
    entries: RwLock<HashMap<RecordKey, CacheEntry<HashMap<String, FieldValue>>>>,
    config: CacheConfig,
    stats: RwLock<CacheStats>,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub expirations: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

impl RecordCache {
    /// Create a new record cache
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            config,
            stats: RwLock::new(CacheStats::default()),
        }
    }

    /// Get a record from cache
    pub async fn get(&self, key: &RecordKey) -> Option<HashMap<String, FieldValue>> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.get_mut(key) {
            if entry.is_expired(self.config.ttl) {
                entries.remove(key);
                let mut stats = self.stats.write().await;
                stats.expirations += 1;
                stats.misses += 1;
                trace!("Cache miss (expired): {:?}", key);
                return None;
            }

            entry.touch();
            let mut stats = self.stats.write().await;
            stats.hits += 1;
            trace!("Cache hit: {:?}", key);
            return Some(entry.value.clone());
        }

        let mut stats = self.stats.write().await;
        stats.misses += 1;
        trace!("Cache miss: {:?}", key);
        None
    }

    /// Put a record in cache
    pub async fn put(&self, key: RecordKey, value: HashMap<String, FieldValue>) {
        let mut entries = self.entries.write().await;

        // Evict if at capacity
        if entries.len() >= self.config.max_entries {
            self.evict_lru(&mut entries).await;
        }

        entries.insert(key.clone(), CacheEntry::new(value));
        debug!("Cached record: {:?}", key);
    }

    /// Invalidate a specific record
    pub async fn invalidate(&self, key: &RecordKey) {
        let mut entries = self.entries.write().await;
        if entries.remove(key).is_some() {
            debug!("Invalidated cache: {:?}", key);
        }
    }

    /// Invalidate all records for a model
    pub async fn invalidate_model(&self, model: &str) {
        let mut entries = self.entries.write().await;
        let keys_to_remove: Vec<RecordKey> = entries
            .keys()
            .filter(|k| k.model == model)
            .cloned()
            .collect();

        for key in &keys_to_remove {
            entries.remove(key);
        }
        debug!("Invalidated {} records for model {}", keys_to_remove.len(), model);
    }

    /// Invalidate all records for a company
    pub async fn invalidate_company(&self, company_id: &str) {
        let mut entries = self.entries.write().await;
        let keys_to_remove: Vec<RecordKey> = entries
            .keys()
            .filter(|k| k.company_id.as_deref() == Some(company_id))
            .cloned()
            .collect();

        for key in &keys_to_remove {
            entries.remove(key);
        }
        debug!("Invalidated {} records for company {}", keys_to_remove.len(), company_id);
    }

    /// Clear all cache entries
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
        debug!("Cache cleared");
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        self.stats.read().await.clone()
    }

    /// Get current cache size
    pub async fn size(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Evict least recently used entry
    async fn evict_lru(&self, entries: &mut HashMap<RecordKey, CacheEntry<HashMap<String, FieldValue>>>) {
        // Find the entry with oldest access time
        if let Some(key) = entries
            .iter()
            .min_by_key(|(_, e)| e.accessed_at)
            .map(|(k, _)| k.clone())
        {
            entries.remove(&key);
            let mut stats = self.stats.write().await;
            stats.evictions += 1;
            trace!("Evicted LRU: {:?}", key);
        }
    }

    /// Run cleanup to remove expired entries
    pub async fn cleanup(&self) {
        let mut entries = self.entries.write().await;
        let now = Instant::now();
        let ttl = self.config.ttl;

        let keys_to_remove: Vec<RecordKey> = entries
            .iter()
            .filter(|(_, e)| e.is_expired(ttl))
            .map(|(k, _)| k.clone())
            .collect();

        let removed_count = keys_to_remove.len();
        for key in keys_to_remove {
            entries.remove(&key);
        }

        if removed_count > 0 {
            let mut stats = self.stats.write().await;
            stats.expirations += removed_count as u64;
            debug!("Cleanup removed {} expired entries", removed_count);
        }
    }
}

/// Dependency tracker for computed field invalidation
pub struct DependencyTracker {
    /// Maps field -> fields that depend on it
    dependencies: RwLock<HashMap<(String, String), Vec<(String, String)>>>,
}

impl DependencyTracker {
    pub fn new() -> Self {
        Self {
            dependencies: RwLock::new(HashMap::new()),
        }
    }

    /// Register a dependency: computed_field depends on source_field
    pub async fn register(
        &self,
        model: &str,
        computed_field: &str,
        source_model: &str,
        source_field: &str,
    ) {
        let mut deps = self.dependencies.write().await;
        let key = (source_model.to_string(), source_field.to_string());
        let entry = deps.entry(key).or_insert_with(Vec::new);
        entry.push((model.to_string(), computed_field.to_string()));
    }

    /// Get all fields that should be invalidated when a source field changes
    pub async fn get_dependents(
        &self,
        source_model: &str,
        source_field: &str,
    ) -> Vec<(String, String)> {
        let deps = self.dependencies.read().await;
        let key = (source_model.to_string(), source_field.to_string());
        deps.get(&key).cloned().unwrap_or_default()
    }
}

impl Default for DependencyTracker {
    fn default() -> Self {
        Self::new()
    }
}
