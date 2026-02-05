//! Vortex ORM - Object-Relational Mapping Layer
//!
//! A powerful ORM designed for large-scale data management with NERC CIP compliance.
//!
//! # Features
//!
//! - Type-safe query builder with lazy evaluation
//! - Computed fields with automatic dependency tracking
//! - Multi-tenant isolation at the query level
//! - Record-level caching with intelligent invalidation
//! - Audit logging for all data mutations
//!
//! # Example
//!
//! ```rust,ignore
//! use vortex_orm::prelude::*;
//!
//! #[derive(Model)]
//! #[vortex(table = "users")]
//! struct User {
//!     #[vortex(primary_key)]
//!     id: Uuid,
//!     name: String,
//!     email: String,
//!     #[vortex(computed, depends_on = ["first_name", "last_name"])]
//!     display_name: String,
//! }
//! ```

pub mod cache;
pub mod connection;
pub mod dialect;
pub mod field;
pub mod migration;
pub mod model;
pub mod pool_manager;
pub mod query;
pub mod registry;
pub mod schema;

pub mod prelude {
    pub use crate::connection::{ConnectionPool, DatabaseConfig};
    pub use crate::dialect::{DatabaseBackend, SqlDialect, NullsPosition};
    #[cfg(feature = "mssql")]
    pub use crate::dialect::MssqlDialect;
    pub use crate::dialect::PostgresDialect;
    pub use crate::field::{Field, FieldDef, FieldType};
    pub use crate::model::{Model, ModelMeta, AccessControl, AccessibleFields, SecureModelExt, NoAccessControl};
    pub use crate::pool_manager::{DatabasePoolManager, PoolManagerConfig};
    pub use crate::query::{Query, QueryBuilder, Filter, OrderBy, SecureQueryBuilder, SecureQuery};
    pub use crate::registry::ModelRegistry;
    pub use vortex_common::{Context, VortexResult, VortexError};
}

pub use prelude::*;
