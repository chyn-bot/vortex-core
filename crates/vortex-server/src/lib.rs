//! Vortex Server - HTTP API Layer
//!
//! Provides REST/JSON-RPC API endpoints and HTML views for Vortex.

pub mod api;
pub mod db;
pub mod middleware;
pub mod routes;
pub mod state;
pub mod views;

pub mod prelude {
    pub use crate::api::{ApiError, ApiResponse};
    pub use crate::db::DbUserLookup;
    pub use crate::middleware::auth::AuthLayer;
    pub use crate::state::AppState;
}

pub use prelude::*;
