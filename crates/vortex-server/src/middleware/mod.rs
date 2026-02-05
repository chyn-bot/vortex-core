//! Server middleware

pub mod auth;
pub mod logging;
pub mod rate_limit;

pub use auth::{auth_middleware, generate_jwt, is_admin, is_system_admin, require_auth, require_auth_html};
