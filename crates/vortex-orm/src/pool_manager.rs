//! Database Pool Manager - manages multiple named database connection pools.
//!
//! Provides lazy pool creation, idle pool eviction, and connection limit management
//! for multi-database deployments (Odoo-style database manager pattern).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::connection::{ConnectionPool, DatabaseConfig};
use vortex_common::{VortexError, VortexResult};

/// Configuration for the database pool manager.
#[derive(Debug, Clone)]
pub struct PoolManagerConfig {
    /// Base connection URL without database name, e.g. "postgres://user:pass@host:5432"
    pub base_url: String,
    /// Global maximum connections across all pools
    pub global_max_connections: u32,
    /// Minimum connections per pool
    pub min_per_pool: u32,
    /// Maximum connections per pool
    pub max_per_pool: u32,
    /// Evict pools idle longer than this duration
    pub pool_idle_timeout: Duration,
    /// Connection acquire timeout per pool
    pub acquire_timeout: Duration,
}

impl Default for PoolManagerConfig {
    fn default() -> Self {
        Self {
            base_url: "postgres://localhost:5432".to_string(),
            global_max_connections: 100,
            min_per_pool: 2,
            max_per_pool: 20,
            pool_idle_timeout: Duration::from_secs(30 * 60), // 30 minutes
            acquire_timeout: Duration::from_secs(30),
        }
    }
}

impl PoolManagerConfig {
    /// Build a full database URL for a given database name.
    pub fn url_for_db(&self, db_name: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), db_name)
    }
}

/// Entry in the pool map, tracking last access time.
struct PoolEntry {
    pool: Arc<ConnectionPool>,
    last_accessed: Instant,
}

/// Manages multiple named database connection pools with lazy creation and idle eviction.
pub struct DatabasePoolManager {
    config: PoolManagerConfig,
    pools: RwLock<HashMap<String, PoolEntry>>,
}

impl DatabasePoolManager {
    /// Create a new pool manager with the given configuration.
    pub fn new(config: PoolManagerConfig) -> Self {
        Self {
            config,
            pools: RwLock::new(HashMap::new()),
        }
    }

    /// Create a pool manager that wraps a single existing pool (backward-compatible mode).
    pub fn single(db_name: &str, pool: Arc<ConnectionPool>) -> Self {
        let mut pools = HashMap::new();
        pools.insert(
            db_name.to_string(),
            PoolEntry {
                pool,
                last_accessed: Instant::now(),
            },
        );
        Self {
            config: PoolManagerConfig::default(),
            pools: RwLock::new(pools),
        }
    }

    /// Get or create a connection pool for the given database name.
    ///
    /// If the pool doesn't exist yet, it is created lazily. Updates last_accessed on every call.
    pub async fn get_pool(&self, db_name: &str) -> VortexResult<Arc<ConnectionPool>> {
        // Fast path: pool already exists
        {
            let mut pools = self.pools.write().await;
            if let Some(entry) = pools.get_mut(db_name) {
                entry.last_accessed = Instant::now();
                return Ok(entry.pool.clone());
            }
        }

        // Slow path: create new pool
        let url = self.config.url_for_db(db_name);
        info!("Creating connection pool for database '{}'", db_name);

        let db_config = DatabaseConfig {
            url,
            min_connections: self.config.min_per_pool,
            max_connections: self.config.max_per_pool,
            acquire_timeout: self.config.acquire_timeout,
            ..DatabaseConfig::default()
        };

        let pool = Arc::new(ConnectionPool::new(db_config).await?);

        let mut pools = self.pools.write().await;
        // Double-check: another task may have created the pool while we were connecting
        if let Some(entry) = pools.get_mut(db_name) {
            entry.last_accessed = Instant::now();
            return Ok(entry.pool.clone());
        }

        pools.insert(
            db_name.to_string(),
            PoolEntry {
                pool: pool.clone(),
                last_accessed: Instant::now(),
            },
        );

        Ok(pool)
    }

    /// Register an existing pool under a name (used for pre-created pools like the master db).
    pub async fn register_pool(&self, db_name: &str, pool: Arc<ConnectionPool>) {
        let mut pools = self.pools.write().await;
        pools.insert(
            db_name.to_string(),
            PoolEntry {
                pool,
                last_accessed: Instant::now(),
            },
        );
    }

    /// Remove and close the pool for the given database name.
    ///
    /// Returns true if the pool was found and removed.
    pub async fn remove_pool(&self, db_name: &str) -> bool {
        let mut pools = self.pools.write().await;
        if let Some(entry) = pools.remove(db_name) {
            entry.pool.close().await;
            info!("Removed and closed pool for database '{}'", db_name);
            true
        } else {
            false
        }
    }

    /// Check if a pool exists for the given database name.
    pub async fn has_pool(&self, db_name: &str) -> bool {
        let pools = self.pools.read().await;
        pools.contains_key(db_name)
    }

    /// List all currently managed database names.
    pub async fn list_databases(&self) -> Vec<String> {
        let pools = self.pools.read().await;
        pools.keys().cloned().collect()
    }

    /// Evict pools that have been idle longer than the configured timeout.
    ///
    /// Should be called periodically from a background task (e.g. every 60 seconds).
    pub async fn evict_idle_pools(&self, protect: &[String]) {
        let now = Instant::now();
        let timeout = self.config.pool_idle_timeout;
        let mut to_remove = Vec::new();

        {
            let pools = self.pools.read().await;
            for (name, entry) in pools.iter() {
                if protect.contains(name) {
                    continue;
                }
                if now.duration_since(entry.last_accessed) > timeout {
                    to_remove.push(name.clone());
                }
            }
        }

        if !to_remove.is_empty() {
            let mut pools = self.pools.write().await;
            for name in &to_remove {
                if let Some(entry) = pools.get(name) {
                    if now.duration_since(entry.last_accessed) > timeout {
                        if let Some(entry) = pools.remove(name) {
                            entry.pool.close().await;
                            warn!("Evicted idle pool for database '{}'", name);
                        }
                    }
                }
            }
        }
    }

    /// Close all pools. Called during server shutdown.
    pub async fn close_all(&self) {
        let mut pools = self.pools.write().await;
        for (name, entry) in pools.drain() {
            info!("Closing pool for database '{}'", name);
            entry.pool.close().await;
        }
    }

    /// Get the pool manager configuration.
    pub fn config(&self) -> &PoolManagerConfig {
        &self.config
    }
}
