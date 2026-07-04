//! Database Pool Manager - manages multiple named database connection pools.
//!
//! Provides lazy pool creation, idle pool eviction, and connection limit management
//! for multi-database deployments (Odoo-style database manager pattern).
//!
//! `global_max_connections` is a hard budget across every managed pool:
//! the sum of all pools' `max_connections` (plus reservations held by
//! in-flight pool creations) never exceeds it. Keep the budget below the
//! Postgres server's own `max_connections`, or tenant pools will win
//! connections the server can't actually grant.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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
    /// This pool's share of the global connection budget.
    max_connections: u32,
    /// Pinned pools (primary DB, master registry) are never evicted.
    pinned: bool,
}

/// How much budget a new pool may claim, or `None` when even the
/// minimum viable pool doesn't fit.
fn plan_allocation(
    global_max: u32,
    committed: u32,
    reserved: u32,
    min_per_pool: u32,
    max_per_pool: u32,
) -> Option<u32> {
    let remaining = global_max.saturating_sub(committed.saturating_add(reserved));
    (remaining >= min_per_pool.max(1)).then(|| remaining.min(max_per_pool))
}

/// Removes its reservation when dropped, so a cancelled or failed pool
/// creation can never leak budget.
struct Reservation<'a> {
    creating: &'a Mutex<HashMap<String, u32>>,
    db_name: String,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.creating.lock().unwrap().remove(&self.db_name);
    }
}

/// Manages multiple named database connection pools with lazy creation and idle eviction.
pub struct DatabasePoolManager {
    config: PoolManagerConfig,
    pools: RwLock<HashMap<String, PoolEntry>>,
    /// Budget reserved by in-flight pool creations, keyed by database
    /// name. Also serves as a per-database creation lock so concurrent
    /// requests for a new tenant produce one pool, not several.
    /// std Mutex: never held across an await.
    creating: Mutex<HashMap<String, u32>>,
}

impl DatabasePoolManager {
    /// Create a new pool manager with the given configuration.
    pub fn new(config: PoolManagerConfig) -> Self {
        Self {
            config,
            pools: RwLock::new(HashMap::new()),
            creating: Mutex::new(HashMap::new()),
        }
    }

    /// Create a pool manager that wraps a single existing pool (backward-compatible mode).
    pub fn single(db_name: &str, pool: Arc<ConnectionPool>) -> Self {
        let max = pool.pool().options().get_max_connections();
        let mut pools = HashMap::new();
        pools.insert(
            db_name.to_string(),
            PoolEntry {
                pool,
                last_accessed: Instant::now(),
                max_connections: max,
                pinned: true,
            },
        );
        Self {
            config: PoolManagerConfig::default(),
            pools: RwLock::new(pools),
            creating: Mutex::new(HashMap::new()),
        }
    }

    /// Sum of `max_connections` across live pools.
    async fn committed_budget(&self) -> u32 {
        self.pools
            .read()
            .await
            .values()
            .map(|e| e.max_connections)
            .sum()
    }

    /// Get or create a connection pool for the given database name.
    ///
    /// If the pool doesn't exist yet, it is created lazily with a
    /// `max_connections` cut to whatever is left of the global budget
    /// (at least `min_per_pool`). When the budget is exhausted, the
    /// least-recently-used unpinned pool that has sat idle for over a
    /// minute is evicted to make room; if there is none, this fails
    /// with a clear error instead of overcommitting the Postgres server.
    pub async fn get_pool(&self, db_name: &str) -> VortexResult<Arc<ConnectionPool>> {
        loop {
            // Fast path: pool already exists
            {
                let mut pools = self.pools.write().await;
                if let Some(entry) = pools.get_mut(db_name) {
                    entry.last_accessed = Instant::now();
                    return Ok(entry.pool.clone());
                }
            }

            // Reserve budget — or discover another task is already
            // creating this pool and wait for it to land.
            let mut evicted_for_budget = false;
            let reservation = loop {
                let committed = self.committed_budget().await;
                {
                    let mut creating = self.creating.lock().unwrap();
                    if creating.contains_key(db_name) {
                        break None;
                    }
                    let reserved: u32 = creating.values().sum();
                    if let Some(alloc) = plan_allocation(
                        self.config.global_max_connections,
                        committed,
                        reserved,
                        self.config.min_per_pool,
                        self.config.max_per_pool,
                    ) {
                        creating.insert(db_name.to_string(), alloc);
                        break Some((
                            alloc,
                            Reservation { creating: &self.creating, db_name: db_name.to_string() },
                        ));
                    }
                }
                // Budget exhausted: try to reclaim from an idle pool once.
                if evicted_for_budget || !self.evict_lru_for_budget().await {
                    return Err(VortexError::DatabaseConnection(format!(
                        "connection budget exhausted: cannot open a pool for '{}' \
                         ({} connections allocated of {} global; no idle pool to evict)",
                        db_name,
                        committed,
                        self.config.global_max_connections,
                    )));
                }
                evicted_for_budget = true;
            };

            let Some((alloc, reservation)) = reservation else {
                // Another task holds the creation slot for this database;
                // let it finish, then re-run the fast path.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };

            let url = self.config.url_for_db(db_name);
            info!(
                "Creating connection pool for database '{}' (max {} of {} global budget)",
                db_name, alloc, self.config.global_max_connections
            );

            let db_config = DatabaseConfig {
                url,
                min_connections: self.config.min_per_pool.min(alloc),
                max_connections: alloc,
                acquire_timeout: self.config.acquire_timeout,
                ..DatabaseConfig::default()
            };

            // Reservation stays alive across the connect so concurrent
            // budget math counts it; its Drop releases it on any exit.
            let pool = Arc::new(ConnectionPool::new(db_config).await?);

            let mut pools = self.pools.write().await;
            // A pool may have been registered while we were connecting
            // (register_pool doesn't go through the creation lock).
            if let Some(entry) = pools.get_mut(db_name) {
                entry.last_accessed = Instant::now();
                let existing = entry.pool.clone();
                drop(pools);
                pool.close().await;
                return Ok(existing);
            }

            pools.insert(
                db_name.to_string(),
                PoolEntry {
                    pool: pool.clone(),
                    last_accessed: Instant::now(),
                    max_connections: alloc,
                    pinned: false,
                },
            );
            drop(pools);
            drop(reservation);

            return Ok(pool);
        }
    }

    /// Evict the least-recently-used unpinned pool that has been idle
    /// for over a minute, to free budget for a new pool. Returns true
    /// if a pool was evicted.
    async fn evict_lru_for_budget(&self) -> bool {
        const PRESSURE_IDLE_GRACE: Duration = Duration::from_secs(60);
        let now = Instant::now();
        let mut pools = self.pools.write().await;
        let victim = pools
            .iter()
            .filter(|(_, e)| !e.pinned)
            .filter(|(_, e)| now.duration_since(e.last_accessed) > PRESSURE_IDLE_GRACE)
            .min_by_key(|(_, e)| e.last_accessed)
            .map(|(name, _)| name.clone());
        match victim {
            Some(name) => {
                if let Some(entry) = pools.remove(&name) {
                    entry.pool.close().await;
                    warn!(
                        "Evicted idle pool for database '{}' to free connection budget",
                        name
                    );
                }
                true
            }
            None => false,
        }
    }

    /// Register an existing pool under a name (used for pre-created pools like the master db).
    ///
    /// Registered pools are pinned: they count against the global budget
    /// but are never evicted.
    pub async fn register_pool(&self, db_name: &str, pool: Arc<ConnectionPool>) {
        let max = pool.pool().options().get_max_connections();
        let mut pools = self.pools.write().await;
        pools.insert(
            db_name.to_string(),
            PoolEntry {
                pool,
                last_accessed: Instant::now(),
                max_connections: max,
                pinned: true,
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
    /// Pinned pools and names in `protect` are never evicted.
    pub async fn evict_idle_pools(&self, protect: &[String]) {
        let now = Instant::now();
        let timeout = self.config.pool_idle_timeout;
        let mut to_remove = Vec::new();

        {
            let pools = self.pools.read().await;
            for (name, entry) in pools.iter() {
                if entry.pinned || protect.contains(name) {
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

#[cfg(test)]
mod tests {
    use super::plan_allocation;

    #[test]
    fn full_allocation_when_budget_is_free() {
        assert_eq!(plan_allocation(100, 0, 0, 2, 20), Some(20));
        assert_eq!(plan_allocation(100, 15, 0, 2, 20), Some(20));
    }

    #[test]
    fn allocation_shrinks_to_remaining_budget() {
        // 100 global, 85 committed → only 15 left for a max-20 pool
        assert_eq!(plan_allocation(100, 85, 0, 2, 20), Some(15));
        // reservations held by in-flight creations count too
        assert_eq!(plan_allocation(100, 70, 15, 2, 20), Some(15));
    }

    #[test]
    fn allocation_refused_below_minimum() {
        assert_eq!(plan_allocation(100, 99, 0, 2, 20), None);
        assert_eq!(plan_allocation(100, 90, 9, 2, 20), None);
        // exactly the minimum still fits
        assert_eq!(plan_allocation(100, 98, 0, 2, 20), Some(2));
    }

    #[test]
    fn overcommitted_budget_saturates_instead_of_wrapping() {
        // committed above global (pre-existing pinned pools can do this)
        assert_eq!(plan_allocation(50, 60, 0, 2, 20), None);
        assert_eq!(plan_allocation(50, 40, 30, 2, 20), None);
    }

    #[test]
    fn zero_min_still_requires_one_connection() {
        assert_eq!(plan_allocation(100, 100, 0, 0, 20), None);
        assert_eq!(plan_allocation(100, 99, 0, 0, 20), Some(1));
    }
}
