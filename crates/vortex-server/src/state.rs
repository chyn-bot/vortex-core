//! Application state

use std::sync::Arc;
use axum::extract::FromRef;
use tracing::info;
use vortex_orm::ConnectionPool;
use vortex_security::{AuditLog, AuthService, RoleManager, SessionManager};
use vortex_module::ModuleLoader;
use vortex_chatter::ChatterService;

use crate::db::DbUserLookup;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub db: Arc<ConnectionPool>,
    /// Session manager
    pub sessions: Arc<SessionManager>,
    /// Role manager
    pub roles: Arc<RoleManager>,
    /// Audit log
    pub audit: Arc<AuditLog>,
    /// Module loader
    pub modules: Arc<ModuleLoader>,
    /// Authentication service
    pub auth: Arc<AuthService>,
    /// Chatter service
    pub chatter: Arc<ChatterService>,
    /// JWT secret for token signing
    pub jwt_secret: Arc<String>,
}

/// Enable plugin handlers to extract `Arc<ConnectionPool>` from `AppState`
impl FromRef<AppState> for Arc<ConnectionPool> {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl AppState {
    /// Create new application state (sync version for compatibility)
    pub fn new(
        db: ConnectionPool,
        sessions: SessionManager,
        roles: RoleManager,
        audit: AuditLog,
        modules: ModuleLoader,
    ) -> Self {
        let db = Arc::new(db);
        let sessions = Arc::new(sessions);
        let audit = Arc::new(audit);

        // Create database-backed user lookup
        let user_lookup = Arc::new(DbUserLookup::new(db.clone()));

        // Create authentication service
        let auth = Arc::new(AuthService::new(
            user_lookup,
            sessions.clone(),
            audit.clone(),
        ));

        // Create chatter service
        let chatter = Arc::new(ChatterService::new(db.clone(), audit.clone()));

        // Get JWT secret from environment or use default for dev
        let jwt_secret = Arc::new(
            std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret-change-in-production".to_string())
        );

        Self {
            db,
            sessions,
            roles: Arc::new(roles),
            audit,
            modules: Arc::new(modules),
            auth,
            chatter,
            jwt_secret,
        }
    }

    /// Create new application state with async initialization (seeds database)
    pub async fn new_with_init(
        db: ConnectionPool,
        sessions: SessionManager,
        roles: RoleManager,
        audit: AuditLog,
        modules: ModuleLoader,
    ) -> Self {
        let db = Arc::new(db);
        let sessions = Arc::new(sessions);
        let audit = Arc::new(audit);

        // Seed core data (roles, default admin if needed)
        if let Err(e) = crate::db::seed_core_data(&db).await {
            tracing::warn!("Failed to seed core data: {}", e);
        }
        if let Err(e) = crate::db::seed_default_admin(&db).await {
            tracing::warn!("Failed to seed default admin: {}", e);
        }
        info!("Database initialization complete");

        // Create database-backed user lookup
        let user_lookup = Arc::new(DbUserLookup::new(db.clone()));

        // Create authentication service
        let auth = Arc::new(AuthService::new(
            user_lookup,
            sessions.clone(),
            audit.clone(),
        ));

        // Create chatter service
        let chatter = Arc::new(ChatterService::new(db.clone(), audit.clone()));

        // Get JWT secret from environment or use default for dev
        let jwt_secret = Arc::new(
            std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret-change-in-production".to_string())
        );

        Self {
            db,
            sessions,
            roles: Arc::new(roles),
            audit,
            modules: Arc::new(modules),
            auth,
            chatter,
            jwt_secret,
        }
    }
}
