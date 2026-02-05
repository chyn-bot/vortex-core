//! SQL dialect abstraction layer
//!
//! This module provides a clean abstraction over database-specific SQL syntax,
//! enabling runtime database selection while maintaining type safety.

mod types;
mod postgres;
#[cfg(feature = "mssql")]
mod mssql;
#[cfg(test)]
mod tests;

pub use types::{DatabaseBackend, NullsPosition};
pub use postgres::PostgresDialect;
#[cfg(feature = "mssql")]
pub use mssql::MssqlDialect;

use crate::field::FieldType;

/// SQL dialect trait for database-specific SQL generation
///
/// This trait abstracts the differences between database engines, allowing
/// the ORM to generate correct SQL for each backend.
pub trait SqlDialect: Send + Sync + 'static {
    /// Get the database backend type
    fn backend(&self) -> DatabaseBackend;

    /// Generate a parameter placeholder for the given index (1-based)
    ///
    /// PostgreSQL: `$1`, `$2`, etc.
    /// SQL Server: `@p1`, `@p2`, etc.
    fn param_placeholder(&self, index: i32) -> String;

    /// Convert a FieldType to the database-specific SQL type
    fn field_type_to_sql(&self, field_type: &FieldType) -> String;

    /// Get the function for current timestamp
    ///
    /// PostgreSQL: `NOW()`
    /// SQL Server: `GETUTCDATE()`
    fn now_function(&self) -> &'static str;

    /// Get the expression for generating a UUID
    ///
    /// PostgreSQL: `gen_random_uuid()`
    /// SQL Server: `NEWID()`
    fn uuid_generate(&self) -> &'static str;

    /// Generate case-insensitive LIKE expression
    ///
    /// PostgreSQL: `column ILIKE $1`
    /// SQL Server: `LOWER(column) LIKE LOWER(@p1)`
    fn ilike_expression(&self, column: &str, param: &str) -> String;

    /// Generate ORDER BY with NULL positioning
    ///
    /// PostgreSQL: `column ASC NULLS FIRST`
    /// SQL Server: `CASE WHEN column IS NULL THEN 0 ELSE 1 END, column ASC`
    fn nulls_order(&self, field: &str, direction: &str, nulls: NullsPosition) -> String;

    /// Generate pagination SQL
    ///
    /// PostgreSQL: `LIMIT 10 OFFSET 20`
    /// SQL Server: `OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY`
    fn pagination_sql(&self, limit: u64, offset: u64) -> String;

    /// Get boolean literal representation
    ///
    /// PostgreSQL: `TRUE` / `FALSE`
    /// SQL Server: `1` / `0`
    fn bool_literal(&self, value: bool) -> &'static str;

    /// Quote an identifier (table or column name)
    ///
    /// PostgreSQL: `"identifier"`
    /// SQL Server: `[identifier]`
    fn quote_identifier(&self, name: &str) -> String;

    /// Get FOR UPDATE syntax
    ///
    /// PostgreSQL: `FOR UPDATE`
    /// SQL Server: `WITH (UPDLOCK, ROWLOCK)`
    fn for_update_sql(&self) -> &'static str;

    /// Get the syntax for date/time interval subtraction
    ///
    /// PostgreSQL: `NOW() - INTERVAL '24 hours'`
    /// SQL Server: `DATEADD(hour, -24, GETUTCDATE())`
    fn date_subtract_hours(&self, hours: u32) -> String;

    /// Check if this dialect supports a specific index method
    fn supports_index_method(&self, method: &str) -> bool;

    /// Get the array aggregation function
    ///
    /// PostgreSQL: `array_agg(column)`
    /// SQL Server: `STRING_AGG(column, ',')`
    fn array_agg(&self, column: &str) -> String;

    /// Get the empty array literal
    ///
    /// PostgreSQL: `ARRAY[]::text[]`
    /// SQL Server: `''` (empty string, needs parsing)
    fn empty_array_literal(&self, element_type: &str) -> String;

    /// Get COALESCE with array fallback
    fn coalesce_array(&self, expr: &str, element_type: &str) -> String;

    /// Generate ON CONFLICT / MERGE syntax for upsert
    fn upsert_syntax(
        &self,
        table: &str,
        columns: &[&str],
        conflict_columns: &[&str],
        update_columns: &[&str],
    ) -> String;

    /// Get the syntax for auto-increment primary key
    fn serial_type(&self) -> &'static str;

    /// Get the syntax for big auto-increment primary key
    fn bigserial_type(&self) -> &'static str;
}

/// Create the appropriate dialect from a database URL
pub fn dialect_from_url(url: &str) -> Option<Box<dyn SqlDialect>> {
    match DatabaseBackend::from_url(url)? {
        DatabaseBackend::Postgres => Some(Box::new(PostgresDialect)),
        #[cfg(feature = "mssql")]
        DatabaseBackend::MsSql => Some(Box::new(MssqlDialect)),
    }
}

/// Create the appropriate dialect from a DatabaseBackend
pub fn dialect_for_backend(backend: DatabaseBackend) -> Box<dyn SqlDialect> {
    match backend {
        DatabaseBackend::Postgres => Box::new(PostgresDialect),
        #[cfg(feature = "mssql")]
        DatabaseBackend::MsSql => Box::new(MssqlDialect),
    }
}
