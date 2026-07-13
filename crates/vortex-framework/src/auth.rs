//! Core auth types and extractors shared across the host binary and
//! every plugin.
//!
//! [`AuthUser`] is the authenticated user context the server's auth
//! middleware injects into the request extensions. Every protected
//! handler extracts it via `Extension<AuthUser>`.
//!
//! [`Db`] is an axum extractor that pulls the request-scoped
//! `PgPool` out of the [`crate::DatabaseContext`] that the auth
//! middleware sets up. This is how plugins get a tenant-correct DB
//! connection without having to know anything about multi-database
//! routing.
//!
//! Both types moved here from `vortex-cli/src/commands/server.rs` in
//! Phase 0.3b so plugin crates can use them without a circular
//! dependency on the binary.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

use crate::state::DatabaseContext;

/// Authenticated user context passed to every protected handler.
///
/// Injected by the host binary's auth middleware into the request
/// extensions; handlers extract it as `Extension<AuthUser>`. The
/// struct is cheap to clone (all `Clone` fields) because axum clones
/// it into every handler that extracts it.
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub full_name: Option<String>,
    pub session_id: Uuid,
    pub roles: Vec<String>,
    /// The `contacts` row this login represents, when it is an **external
    /// portal user** (customer/vendor self-service). `None` for internal
    /// staff. Portal document queries scope on this — never on a request
    /// parameter — so a portal user can only ever see their own partner's data.
    pub contact_id: Option<Uuid>,
    /// True for external portal logins. Portal users are confined to the
    /// `/portal/*` surface: the internal `auth_middleware` rejects them, so a
    /// portal user can never reach a back-office route regardless of roles.
    pub is_portal: bool,
}

impl AuthUser {
    /// Check if the user has a specific role (case-sensitive match).
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Convenience: is this the system administrator role?
    pub fn is_system_admin(&self) -> bool {
        self.has_role("System Administrator")
    }

    /// Convenience: any admin-flavored role?
    /// A portal user is never an admin, whatever roles are attached.
    pub fn is_admin(&self) -> bool {
        !self.is_portal
            && (self.has_role("System Administrator") || self.has_role("Administrator"))
    }

    /// The partner (`contacts.id`) a portal login is bound to, if any.
    /// Returns `None` for internal staff. Portal handlers use this as the
    /// tamper-proof scope for every query.
    pub fn portal_contact_id(&self) -> Option<Uuid> {
        if self.is_portal {
            self.contact_id
        } else {
            None
        }
    }
}

/// Extractor that hands a handler the request-scoped `PgPool`.
///
/// The auth middleware resolves the tenant database for the current
/// session and stores a [`DatabaseContext`] in the request extensions.
/// This extractor pulls that out and exposes just the inner pool so
/// handlers can write `Db(db): Db` in their signature and use
/// `&db` as a `&PgPool`.
///
/// Falls back to `INTERNAL_SERVER_ERROR` if the middleware was never
/// run for this request — which is always a programming error, never
/// a user-facing one, because all protected routes go through auth.
pub struct Db(pub PgPool);

impl<S: Send + Sync> FromRequestParts<S> for Db {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<DatabaseContext>()
            .map(|ctx| Db(ctx.pool.pool().clone()))
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}
