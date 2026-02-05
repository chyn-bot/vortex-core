//! Shared types for SQL dialects

use serde::{Deserialize, Serialize};

/// Database backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DatabaseBackend {
    /// PostgreSQL database
    Postgres,
    /// Microsoft SQL Server database
    #[cfg(feature = "mssql")]
    MsSql,
}

impl DatabaseBackend {
    /// Get the backend name as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseBackend::Postgres => "postgres",
            #[cfg(feature = "mssql")]
            DatabaseBackend::MsSql => "mssql",
        }
    }

    /// Parse backend from connection URL scheme
    pub fn from_url(url: &str) -> Option<Self> {
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Some(DatabaseBackend::Postgres)
        } else {
            #[cfg(feature = "mssql")]
            if url.starts_with("mssql://") || url.starts_with("sqlserver://") {
                return Some(DatabaseBackend::MsSql);
            }
            None
        }
    }
}

impl std::fmt::Display for DatabaseBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Position for NULL values in ORDER BY
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NullsPosition {
    /// Database default behavior
    #[default]
    Default,
    /// NULLs come first
    First,
    /// NULLs come last
    Last,
}
