//! Record caching with intelligent invalidation

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, trace};
use vortex_common::FieldValue;

/// Postgres `NOTIFY` channel used to broadcast record-cache invalidations to
/// every app instance connected to the same database (Grid, cross-process).
pub const CACHE_INVALIDATE_CHANNEL: &str = "vortex_cache_invalidate";

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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecordKey {
    #[serde(rename = "m")]
    pub model: String,
    #[serde(rename = "p")]
    pub pk: String,
    #[serde(rename = "c", default, skip_serializing_if = "Option::is_none")]
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

    /// Serialize this key to a compact JSON payload for a `pg_notify`
    /// broadcast on [`CACHE_INVALIDATE_CHANNEL`].
    pub fn to_notify_payload(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse a key from a `NOTIFY` payload produced by [`Self::to_notify_payload`].
    /// Returns `None` on malformed input (a bad payload must not crash the listener).
    pub fn from_notify_payload(payload: &str) -> Option<Self> {
        serde_json::from_str(payload).ok()
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
    /// Per-model opt-in allowlist. Read-through caching is applied **only**
    /// to models named here. Empty = cache nothing (the safe default), which
    /// keeps audit/session/token tables out of the cache unless a deployment
    /// deliberately opts them in.
    pub models: HashSet<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            ttl: Duration::from_secs(300), // 5 minutes
            cleanup_interval: Duration::from_secs(60),
            models: HashSet::new(),
        }
    }
}

impl CacheConfig {
    /// Build a cache configuration from environment, or `None` when caching is
    /// disabled (the default). This is the global kill-switch:
    ///
    /// - `VORTEX_CACHE_ENABLED` — `1`/`true`/`yes`/`on` turns the record cache
    ///   on. Absent or anything else → `None` (caching off).
    /// - `VORTEX_CACHE_MODELS` — comma-separated per-model opt-in allowlist
    ///   (`ir_model.name` values). Nothing is cached until a model is listed.
    /// - `VORTEX_CACHE_TTL_SECS` / `VORTEX_CACHE_MAX_ENTRIES` — optional tuning.
    ///
    /// The cache is process-local; do not enable it across multiple app
    /// instances without cross-process invalidation (see the pool's
    /// `LISTEN/NOTIFY` invalidation wiring).
    pub fn from_env() -> Option<Self> {
        let enabled = std::env::var("VORTEX_CACHE_ENABLED")
            .ok()
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        let mut cfg = Self::default();
        if let Ok(models) = std::env::var("VORTEX_CACHE_MODELS") {
            cfg.models = models
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(ttl) = std::env::var("VORTEX_CACHE_TTL_SECS") {
            if let Ok(n) = ttl.parse::<u64>() {
                cfg.ttl = Duration::from_secs(n);
            }
        }
        if let Ok(max) = std::env::var("VORTEX_CACHE_MAX_ENTRIES") {
            if let Ok(n) = max.parse::<usize>() {
                cfg.max_entries = n;
            }
        }
        Some(cfg)
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

    /// Whether records of `model` are eligible for read-through caching, per
    /// the per-model opt-in allowlist. Callers must gate `get`/`put` on this so
    /// that non-opted-in models (audit, sessions, tokens) are never cached.
    pub fn is_cacheable(&self, model: &str) -> bool {
        self.config.models.contains(model)
    }

    /// The configuration this cache was built with.
    pub fn config(&self) -> &CacheConfig {
        &self.config
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_with(models: &[&str]) -> RecordCache {
        let mut cfg = CacheConfig::default();
        cfg.models = models.iter().map(|s| s.to_string()).collect();
        RecordCache::new(cfg)
    }

    fn rec(name: &str) -> HashMap<String, FieldValue> {
        let mut m = HashMap::new();
        m.insert("name".to_string(), FieldValue::String(name.to_string()));
        m
    }

    #[tokio::test]
    async fn miss_then_put_then_hit() {
        let cache = cache_with(&["Widget"]);
        let key = RecordKey::new("Widget", "1");

        assert!(cache.get(&key).await.is_none());
        cache.put(key.clone(), rec("v1")).await;
        let hit = cache.get(&key).await.expect("should hit");
        assert_eq!(hit.get("name"), Some(&FieldValue::String("v1".into())));

        let stats = cache.stats().await;
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn invalidate_removes_entry() {
        let cache = cache_with(&["Widget"]);
        let key = RecordKey::new("Widget", "1");
        cache.put(key.clone(), rec("v1")).await;
        cache.invalidate(&key).await;
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn company_scoping_isolates_keys() {
        let cache = cache_with(&["Widget"]);
        let a = RecordKey::new("Widget", "1").with_company("aaaaaaaa-0000-0000-0000-000000000001");
        let b = RecordKey::new("Widget", "1").with_company("bbbbbbbb-0000-0000-0000-000000000002");
        cache.put(a.clone(), rec("tenant-a")).await;
        assert!(cache.get(&b).await.is_none(), "other tenant must not see it");
        assert_eq!(
            cache.get(&a).await.and_then(|v| v.get("name").cloned()),
            Some(FieldValue::String("tenant-a".into()))
        );
    }

    #[test]
    fn is_cacheable_respects_allowlist() {
        let cache = cache_with(&["Widget", "Gadget"]);
        assert!(cache.is_cacheable("Widget"));
        assert!(cache.is_cacheable("Gadget"));
        assert!(!cache.is_cacheable("audit_log"));
        // Empty allowlist (the default) caches nothing.
        let none = RecordCache::new(CacheConfig::default());
        assert!(!none.is_cacheable("Widget"));
    }

    #[test]
    fn notify_payload_roundtrips() {
        let k = RecordKey::new("Widget", "42").with_company("11111111-2222-3333-4444-555555555555");
        let payload = k.to_notify_payload();
        assert_eq!(RecordKey::from_notify_payload(&payload), Some(k));

        // Company-less key roundtrips too.
        let k2 = RecordKey::new("Widget", "7");
        assert_eq!(RecordKey::from_notify_payload(&k2.to_notify_payload()), Some(k2));

        // Malformed payloads never panic — they just yield None.
        assert_eq!(RecordKey::from_notify_payload("not json"), None);
        assert_eq!(RecordKey::from_notify_payload(""), None);
    }

    #[tokio::test]
    async fn expired_entry_is_a_miss() {
        let mut cfg = CacheConfig::default();
        cfg.ttl = Duration::from_millis(0); // everything is immediately stale
        cfg.models = ["Widget".to_string()].into_iter().collect();
        let cache = RecordCache::new(cfg);
        let key = RecordKey::new("Widget", "1");
        cache.put(key.clone(), rec("v1")).await;
        // ttl == 0 → is_expired is true on the next read.
        assert!(cache.get(&key).await.is_none());
        let stats = cache.stats().await;
        assert_eq!(stats.expirations, 1);
    }
}
