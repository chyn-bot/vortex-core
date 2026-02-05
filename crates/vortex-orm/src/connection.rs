//! Database connection pool and configuration

use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use vortex_common::{VortexError, VortexResult};

use crate::dialect::{DatabaseBackend, SqlDialect, PostgresDialect};

#[cfg(feature = "mssql")]
use crate::dialect::MssqlDialect;

// Re-export row types for external use
pub use sqlx::postgres::PgRow;
#[cfg(feature = "mssql")]
pub use sqlx::mssql::MssqlRow;

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Connection URL (postgres://... or mssql://...)
    pub url: String,
    /// Minimum number of connections in the pool
    pub min_connections: u32,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Connection acquisition timeout
    pub acquire_timeout: Duration,
    /// Idle connection timeout
    pub idle_timeout: Duration,
    /// Maximum connection lifetime
    pub max_lifetime: Duration,
    /// Enable SSL
    pub ssl_mode: SslMode,
    /// Application name for monitoring
    pub application_name: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://localhost/vortex".to_string(),
            min_connections: 5,
            max_connections: 100,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
            ssl_mode: SslMode::Prefer,
            application_name: "vortex".to_string(),
        }
    }
}

impl DatabaseConfig {
    /// Create config from environment variables
    pub fn from_env() -> VortexResult<Self> {
        let url = std::env::var("DATABASE_URL").map_err(|_| {
            VortexError::ConfigurationError("DATABASE_URL environment variable not set".to_string())
        })?;

        let mut config = Self::default();
        config.url = url;

        if let Ok(min) = std::env::var("DATABASE_MIN_CONNECTIONS") {
            config.min_connections = min.parse().unwrap_or(5);
        }
        if let Ok(max) = std::env::var("DATABASE_MAX_CONNECTIONS") {
            config.max_connections = max.parse().unwrap_or(100);
        }
        if let Ok(ssl) = std::env::var("DATABASE_SSL_MODE") {
            config.ssl_mode = ssl.parse().unwrap_or(SslMode::Prefer);
        }

        Ok(config)
    }

    /// Detect the database backend from the URL
    pub fn backend(&self) -> Option<DatabaseBackend> {
        DatabaseBackend::from_url(&self.url)
    }
}

/// SSL mode for database connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SslMode {
    Disable,
    #[default]
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl std::str::FromStr for SslMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disable" => Ok(SslMode::Disable),
            "prefer" => Ok(SslMode::Prefer),
            "require" => Ok(SslMode::Require),
            "verify-ca" | "verify_ca" => Ok(SslMode::VerifyCa),
            "verify-full" | "verify_full" => Ok(SslMode::VerifyFull),
            _ => Err(()),
        }
    }
}

/// Inner pool type supporting multiple backends
enum PoolInner {
    Postgres(sqlx::postgres::PgPool),
    #[cfg(feature = "mssql")]
    MsSql(sqlx::mssql::MssqlPool),
}

/// Connection pool wrapper with dialect support
#[derive(Clone)]
pub struct ConnectionPool {
    inner: Arc<PoolInner>,
    dialect: Arc<dyn SqlDialect>,
    config: DatabaseConfig,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub async fn new(config: DatabaseConfig) -> VortexResult<Self> {
        let backend = config.backend().ok_or_else(|| {
            VortexError::ConfigurationError(format!(
                "Unsupported database URL scheme: {}",
                config.url
            ))
        })?;

        info!(
            "Creating {} connection pool: min={}, max={}",
            backend, config.min_connections, config.max_connections
        );

        let (inner, dialect): (PoolInner, Arc<dyn SqlDialect>) = match backend {
            DatabaseBackend::Postgres => {
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .min_connections(config.min_connections)
                    .max_connections(config.max_connections)
                    .acquire_timeout(config.acquire_timeout)
                    .idle_timeout(Some(config.idle_timeout))
                    .max_lifetime(Some(config.max_lifetime))
                    .connect(&config.url)
                    .await
                    .map_err(|e| VortexError::DatabaseConnection(e.to_string()))?;

                // Verify connection
                sqlx::query("SELECT 1")
                    .fetch_one(&pool)
                    .await
                    .map_err(|e| VortexError::DatabaseConnection(e.to_string()))?;

                (PoolInner::Postgres(pool), Arc::new(PostgresDialect))
            }
            #[cfg(feature = "mssql")]
            DatabaseBackend::MsSql => {
                let pool = sqlx::mssql::MssqlPoolOptions::new()
                    .min_connections(config.min_connections)
                    .max_connections(config.max_connections)
                    .acquire_timeout(config.acquire_timeout)
                    .idle_timeout(Some(config.idle_timeout))
                    .max_lifetime(Some(config.max_lifetime))
                    .connect(&config.url)
                    .await
                    .map_err(|e| VortexError::DatabaseConnection(e.to_string()))?;

                // Verify connection
                sqlx::query("SELECT 1")
                    .fetch_one(&pool)
                    .await
                    .map_err(|e| VortexError::DatabaseConnection(e.to_string()))?;

                (PoolInner::MsSql(pool), Arc::new(MssqlDialect))
            }
        };

        info!("Connection pool created successfully for {}", backend);

        Ok(Self {
            inner: Arc::new(inner),
            dialect,
            config,
        })
    }

    /// Wrap an existing PostgreSQL pool into a ConnectionPool
    pub fn from_pg_pool(pool: sqlx::postgres::PgPool, url: &str) -> Self {
        let mut config = DatabaseConfig::default();
        config.url = url.to_string();
        Self {
            inner: Arc::new(PoolInner::Postgres(pool)),
            dialect: Arc::new(PostgresDialect),
            config,
        }
    }

    /// Get the SQL dialect for this connection
    pub fn dialect(&self) -> &dyn SqlDialect {
        &*self.dialect
    }

    /// Get the database backend
    pub fn backend(&self) -> DatabaseBackend {
        self.dialect.backend()
    }

    /// Get the inner PostgreSQL pool (if using PostgreSQL)
    ///
    /// Returns None if connected to a different backend.
    pub fn pg_pool(&self) -> Option<&sqlx::postgres::PgPool> {
        match &*self.inner {
            PoolInner::Postgres(pool) => Some(pool),
            #[cfg(feature = "mssql")]
            _ => None,
        }
    }

    /// Get the inner MSSQL pool (if using SQL Server)
    ///
    /// Returns None if connected to a different backend.
    #[cfg(feature = "mssql")]
    pub fn mssql_pool(&self) -> Option<&sqlx::mssql::MssqlPool> {
        match &*self.inner {
            PoolInner::MsSql(pool) => Some(pool),
            _ => None,
        }
    }

    /// Get the inner pool reference for PostgreSQL (backward compatibility)
    ///
    /// # Panics
    /// Panics if the connection is not PostgreSQL.
    pub fn pool(&self) -> &sqlx::postgres::PgPool {
        self.pg_pool().expect("Expected PostgreSQL connection")
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        match &*self.inner {
            PoolInner::Postgres(pool) => PoolStats {
                size: pool.size(),
                idle: pool.num_idle(),
                max_connections: self.config.max_connections,
            },
            #[cfg(feature = "mssql")]
            PoolInner::MsSql(pool) => PoolStats {
                size: pool.size(),
                idle: pool.num_idle(),
                max_connections: self.config.max_connections,
            },
        }
    }

    /// Check if the database is healthy
    pub async fn health_check(&self) -> VortexResult<()> {
        match &*self.inner {
            PoolInner::Postgres(pool) => {
                sqlx::query("SELECT 1")
                    .fetch_one(pool)
                    .await
                    .map_err(|e| VortexError::DatabaseConnection(e.to_string()))?;
            }
            #[cfg(feature = "mssql")]
            PoolInner::MsSql(pool) => {
                sqlx::query("SELECT 1")
                    .fetch_one(pool)
                    .await
                    .map_err(|e| VortexError::DatabaseConnection(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Execute a raw SQL query (PostgreSQL only for now)
    pub async fn execute(&self, sql: &str) -> VortexResult<u64> {
        match &*self.inner {
            PoolInner::Postgres(pool) => {
                let result = sqlx::query(sql)
                    .execute(pool)
                    .await
                    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                Ok(result.rows_affected())
            }
            #[cfg(feature = "mssql")]
            PoolInner::MsSql(pool) => {
                let result = sqlx::query(sql)
                    .execute(pool)
                    .await
                    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                Ok(result.rows_affected())
            }
        }
    }

    /// Fetch rows from a raw SQL query (PostgreSQL only)
    pub async fn fetch_all(&self, sql: &str) -> VortexResult<Vec<PgRow>> {
        match &*self.inner {
            PoolInner::Postgres(pool) => sqlx::query(sql)
                .fetch_all(pool)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string())),
            #[cfg(feature = "mssql")]
            _ => Err(VortexError::QueryExecution(
                "fetch_all with PgRow not supported for MSSQL".to_string(),
            )),
        }
    }

    /// Fetch a single row (PostgreSQL only)
    pub async fn fetch_one(&self, sql: &str) -> VortexResult<PgRow> {
        match &*self.inner {
            PoolInner::Postgres(pool) => sqlx::query(sql)
                .fetch_one(pool)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string())),
            #[cfg(feature = "mssql")]
            _ => Err(VortexError::QueryExecution(
                "fetch_one with PgRow not supported for MSSQL".to_string(),
            )),
        }
    }

    /// Fetch an optional row (PostgreSQL only)
    pub async fn fetch_optional(&self, sql: &str) -> VortexResult<Option<PgRow>> {
        match &*self.inner {
            PoolInner::Postgres(pool) => sqlx::query(sql)
                .fetch_optional(pool)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string())),
            #[cfg(feature = "mssql")]
            _ => Err(VortexError::QueryExecution(
                "fetch_optional with PgRow not supported for MSSQL".to_string(),
            )),
        }
    }

    /// Begin a transaction
    pub async fn begin(&self) -> VortexResult<Transaction> {
        match &*self.inner {
            PoolInner::Postgres(pool) => {
                let tx = pool
                    .begin()
                    .await
                    .map_err(|e| VortexError::DatabaseConnection(e.to_string()))?;
                Ok(Transaction {
                    inner: TransactionInner::Postgres(tx),
                })
            }
            #[cfg(feature = "mssql")]
            PoolInner::MsSql(pool) => {
                let tx = pool
                    .begin()
                    .await
                    .map_err(|e| VortexError::DatabaseConnection(e.to_string()))?;
                Ok(Transaction {
                    inner: TransactionInner::MsSql(tx),
                })
            }
        }
    }

    /// Close the pool
    pub async fn close(&self) {
        info!("Closing connection pool");
        match &*self.inner {
            PoolInner::Postgres(pool) => pool.close().await,
            #[cfg(feature = "mssql")]
            PoolInner::MsSql(pool) => pool.close().await,
        }
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub size: u32,
    pub idle: usize,
    pub max_connections: u32,
}

/// Inner transaction type
enum TransactionInner {
    Postgres(sqlx::Transaction<'static, sqlx::Postgres>),
    #[cfg(feature = "mssql")]
    MsSql(sqlx::Transaction<'static, sqlx::Mssql>),
}

/// Database transaction wrapper
pub struct Transaction {
    inner: TransactionInner,
}

impl Transaction {
    /// Commit the transaction
    pub async fn commit(self) -> VortexResult<()> {
        match self.inner {
            TransactionInner::Postgres(tx) => tx
                .commit()
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string())),
            #[cfg(feature = "mssql")]
            TransactionInner::MsSql(tx) => tx
                .commit()
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string())),
        }
    }

    /// Rollback the transaction
    pub async fn rollback(self) -> VortexResult<()> {
        match self.inner {
            TransactionInner::Postgres(tx) => tx
                .rollback()
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string())),
            #[cfg(feature = "mssql")]
            TransactionInner::MsSql(tx) => tx
                .rollback()
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string())),
        }
    }

    /// Execute a query within the transaction
    pub async fn execute(&mut self, sql: &str) -> VortexResult<u64> {
        match &mut self.inner {
            TransactionInner::Postgres(tx) => {
                let result = sqlx::query(sql)
                    .execute(&mut **tx)
                    .await
                    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                Ok(result.rows_affected())
            }
            #[cfg(feature = "mssql")]
            TransactionInner::MsSql(tx) => {
                let result = sqlx::query(sql)
                    .execute(&mut **tx)
                    .await
                    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                Ok(result.rows_affected())
            }
        }
    }
}
