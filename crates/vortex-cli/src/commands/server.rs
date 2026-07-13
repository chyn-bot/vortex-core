//! Server command with real database authentication

use anyhow::Result;
use axum::{
    extract::{Form, FromRequestParts, Path, Query, Request, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{delete, get, patch, post},
    Extension, Router,
};
use sqlx::{postgres::PgPoolOptions, Column, PgPool, Row};
use chrono::Datelike;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use tracing::{error, info, warn};
use vortex_framework::{
    build_pagination_html, build_sidebar, error_response, format_number, format_time_ago,
    forbidden_page, get_initials, html_escape, AppState, AuthUser, DatabaseContext, Db,
    PluginRegistry,
};
use vortex_orm::ConnectionPool;
use vortex_policy::{Decision, PgPolicyStore, PolicyPrincipal, PolicyResource, PolicyService};
use vortex_security::audit::PgAuditStorage;
use vortex_security::audit::verify::{verify_chain, VerifyOptions, DEFAULT_CLOCK_SKEW_SECONDS};
use vortex_security::signing::{
    build_signing_key, Pkcs11Config, SigningBackendConfig, SigningKey, SigningMode,
};
use vortex_security::{AuditAction, AuditEntry, AuditLog, AuditSeverity};
use vortex_server::middleware::rate_limit::{RateLimiter, RateLimitConfig};
use vortex_orm::pool_manager::{DatabasePoolManager, PoolManagerConfig};

// Re-export for in-crate handler code that references `AppState` and
// `DatabaseContext` without an import path. The canonical definitions
// live in `vortex-framework::state` — see that crate for field docs.
// Using `pub use` rather than a local redefinition keeps the types
// identical across crate boundaries so plugins can share `AppState`.

/// Middleware for plugin PUBLIC routes (`Plugin::public_routes`) —
/// anonymous, but never tenant-blind: resolves the tenant from the
/// request Host exactly like the login flow does (subdomain → tenant
/// under `db_filter`, else the default database) and injects the
/// `DatabaseContext` so `Db`/pool extractors work. No `AuthUser` is
/// inserted — public handlers must not extract one.
async fn public_context_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let db_name = resolve_database(&state, request.headers(), None).await;
    let pool = match state.pool_manager.get_pool(&db_name).await {
        Ok(p) => p,
        Err(e) => {
            error!("public route: pool for '{}' unavailable: {}", db_name, e);
            return (StatusCode::SERVICE_UNAVAILABLE, "Service unavailable").into_response();
        }
    };
    let installed_modules: HashSet<String> = sqlx::query_scalar(
        "SELECT technical_name FROM installed_modules WHERE state = 'installed'",
    )
    .fetch_all(pool.pool())
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    request.extensions_mut().insert(pool.clone());
    request.extensions_mut().insert(DatabaseContext {
        db_name,
        pool,
        installed_modules,
    });
    next.run(request).await
}

/// Per-plugin gate on public routes: 404 unless the plugin is
/// installed for the tenant the request resolved to. Runs inside
/// `public_context_middleware`, so the `DatabaseContext` is present.
async fn public_module_gate(
    plugin_name: &'static str,
    request: Request,
    next: Next,
) -> Response {
    let installed = request
        .extensions()
        .get::<DatabaseContext>()
        .map(|ctx| ctx.installed_modules.contains(plugin_name))
        .unwrap_or(false);
    if !installed {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }
    next.run(request).await
}

/// Auth middleware - verifies session and injects AuthUser + DatabaseContext
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract session cookie
    let session_cookie = request
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .find_map(|c| {
                    let c = c.trim();
                    if c.starts_with("session=") {
                        Some(c.trim_start_matches("session=").to_string())
                    } else {
                        None
                    }
                })
        });

    let Some(cookie_value) = session_cookie else {
        // No browser cookie. If the client presented a Bearer token (the
        // field app calling plugin routes like `/sesb-eam/api/v1/*`), resolve
        // it and speak JSON; otherwise this is a browser → redirect to login.
        if request.headers().get(header::AUTHORIZATION).is_some() {
            match resolve_bearer(&state, request.headers()).await {
                Some((auth_user, pool, db_ctx, tok)) => {
                    request.extensions_mut().insert(auth_user);
                    request.extensions_mut().insert(tok);
                    request.extensions_mut().insert(pool);
                    request.extensions_mut().insert(db_ctx);
                    return next.run(request).await;
                }
                None => {
                    return api_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        "Invalid, expired, or revoked token.",
                    );
                }
            }
        }
        warn!("No session cookie found, redirecting to login");
        return Redirect::to("/login").into_response();
    };

    // Parse db_name|token or legacy plain token
    let (db_name, token) = if let Some(pos) = cookie_value.find('|') {
        (cookie_value[..pos].to_string(), cookie_value[pos + 1..].to_string())
    } else {
        // Legacy cookie without db name — use default database
        (state.default_db.clone(), cookie_value)
    };

    // Validate db_name to prevent injection via crafted cookies
    if !db_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return redirect_to_login_with_message("Invalid session");
    }

    // Get pool for this database
    let pool = match state.pool_manager.get_pool(&db_name).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to get pool for database '{}': {}", db_name, e);
            return redirect_to_login_with_message("Database unavailable");
        }
    };
    let db = pool.pool();

    // Hash the token to look up in database
    let token_hash = hash_token(&token);

    // Verify session in database
    let session = sqlx::query_as::<_, SessionWithUser>(
        r#"
        SELECT
            s.id as session_id,
            s.user_id,
            s.expires_at,
            s.last_activity_at,
            s.revoked,
            u.username,
            u.full_name,
            u.active,
            u.locked,
            u.is_portal,
            u.contact_id
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token_hash = $1
        "#
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await;

    match session {
        Ok(Some(session)) => {
            // Check if session is valid
            if session.revoked {
                warn!("Session revoked for user {}", session.username);
                return redirect_to_login_with_message("Session expired");
            }
            if session.expires_at < chrono::Utc::now() {
                warn!("Session expired for user {}", session.username);
                return redirect_to_login_with_message("Session expired");
            }
            if !session.active {
                warn!("User {} is disabled", session.username);
                return redirect_to_login_with_message("Account disabled");
            }
            if session.locked {
                warn!("User {} is locked", session.username);
                return redirect_to_login_with_message("Account locked");
            }
            // Hard isolation boundary: an external portal user's session must
            // never grant access to the internal back-office tree, whatever
            // roles are attached. Bounce them to their own surface.
            if session.is_portal {
                return Redirect::to("/portal").into_response();
            }

            // Update last activity (extends session on activity).
            // Throttled to once a minute per session: refreshing on
            // every request would turn each page's burst of API calls
            // into that many row updates + WAL records on a hot table,
            // and a 30-minute sliding window doesn't need sub-minute
            // precision.
            let refresh_due = session
                .last_activity_at
                .map_or(true, |t| chrono::Utc::now() - t > chrono::Duration::seconds(60));
            if refresh_due {
                let _ = sqlx::query(
                    "UPDATE sessions SET last_activity_at = NOW(), expires_at = NOW() + INTERVAL '30 minutes' WHERE id = $1"
                )
                .bind(&session.session_id)
                .execute(db)
                .await;
            }

            // Fetch user roles
            let roles: Vec<String> = sqlx::query_scalar(
                r#"
                SELECT r.name
                FROM roles r
                JOIN user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = $1
                "#
            )
            .bind(session.user_id)
            .fetch_all(db)
            .await
            .unwrap_or_default();

            // Inject AuthUser into request extensions
            let auth_user = AuthUser {
                id: session.user_id,
                username: session.username,
                full_name: session.full_name,
                session_id: session.session_id,
                roles,
                contact_id: session.contact_id,
                is_portal: session.is_portal,
            };
            request.extensions_mut().insert(auth_user);

            // Query installed modules for this specific database
            let db_installed_modules: HashSet<String> = sqlx::query_scalar(
                "SELECT technical_name FROM installed_modules WHERE state = 'installed'"
            )
            .fetch_all(db)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();

            // Inject Arc<ConnectionPool> for plugin handlers (Extension-based extraction)
            request.extensions_mut().insert(pool.clone());

            // Inject DatabaseContext for downstream extractors (Db, InstalledModules)
            request.extensions_mut().insert(DatabaseContext {
                db_name,
                pool,
                installed_modules: db_installed_modules,
            });

            next.run(request).await
        }
        Ok(None) => {
            warn!("Invalid session token");
            redirect_to_login_with_message("Invalid session")
        }
        Err(e) => {
            error!("Database error checking session: {}", e);
            redirect_to_login_with_message("Authentication error")
        }
    }
}

#[derive(sqlx::FromRow)]
struct SessionWithUser {
    session_id: uuid::Uuid,
    user_id: uuid::Uuid,
    expires_at: chrono::DateTime<chrono::Utc>,
    last_activity_at: Option<chrono::DateTime<chrono::Utc>>,
    revoked: bool,
    username: String,
    full_name: Option<String>,
    active: bool,
    locked: bool,
    is_portal: bool,
    contact_id: Option<uuid::Uuid>,
}

fn redirect_to_login_with_message(_message: &str) -> Response {
    // Clear the invalid session cookie and redirect
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".parse().unwrap(),
    );
    (headers, Redirect::to("/login")).into_response()
}

// ─── Public REST API (/api/v1) ────────────────────────────────────────────
// A machine-to-machine surface authenticated by bearer tokens (see
// `vortex_framework::api`). Unlike the cookie middleware above — which serves
// browsers and redirects to /login — this path speaks JSON and returns 401.
// A token authenticates *as a user*, inheriting that user's roles; writes
// additionally require the token's `write` scope. Every call is audited.

/// Uniform JSON error envelope: `{"error":{"code","message"}}`.
fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(serde_json::json!({"error": {"code": code, "message": message}}))).into_response()
}

/// Write one audit entry for an API operation, scoped to the tenant database.
/// `id` is the record UUID for single-record ops, or `None` for collection
/// events (list views) where `resource_id` (a UUID column) must stay null.
async fn api_audit(
    state: &AppState,
    db_name: &str,
    user: &AuthUser,
    action: AuditAction,
    severity: AuditSeverity,
    model: &str,
    id: Option<&str>,
    details: serde_json::Value,
) {
    let mut entry = AuditEntry::new(action, severity)
        .with_database(db_name)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_resource_name(model)
        .with_details(details);
    if let Some(id) = id {
        entry = entry.with_resource(model, id);
    }
    if let Err(e) = state.audit.log(entry).await {
        error!("API audit write failed: {e}");
    }
}

/// Bearer-token auth for `/api/v1/*`. Resolves the token against the tenant
/// database named by `X-Vortex-Database` (default DB if absent), then injects
/// the same `AuthUser` / `DatabaseContext` the cookie path does, plus the
/// `ResolvedToken` for scope checks. Any failure returns a JSON 401/4xx.
async fn api_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let secret = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string());
    let Some(secret) = secret.filter(|s| !s.is_empty()) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "missing_bearer",
            "Provide credentials as 'Authorization: Bearer <token>'.",
        );
    };

    // Tenant selection mirrors the login cookie's db|token split.
    let db_name = request
        .headers()
        .get("x-vortex-database")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| state.default_db.clone());
    if !db_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return api_error(StatusCode::BAD_REQUEST, "invalid_database", "Invalid X-Vortex-Database header.");
    }

    let pool = match state.pool_manager.get_pool(&db_name).await {
        Ok(p) => p,
        Err(_) => return api_error(StatusCode::SERVICE_UNAVAILABLE, "database_unavailable", "Database unavailable."),
    };
    let db = pool.pool();

    // A mobile access token (vtxa_…) takes priority over a service api_token,
    // so the same `/api/v1/*` surface serves both the field app and backend
    // integrations. Both resolve to the owning user + roles.
    let tok = if let Some(m) = vortex_framework::mobile_auth::resolve_access(db, &secret).await {
        vortex_framework::mobile_auth::touch_last_used(db, m.token_id).await;
        vortex_framework::api::ResolvedToken {
            token_id: m.token_id,
            user_id: m.user_id,
            username: m.username,
            full_name: m.full_name,
            roles: m.roles,
            scopes: m.scopes,
        }
    } else if let Some(t) = vortex_framework::api::resolve_token(db, &secret).await {
        vortex_framework::api::touch_last_used(db, t.token_id).await;
        t
    } else {
        return api_error(StatusCode::UNAUTHORIZED, "invalid_token", "Invalid, expired, or revoked token.");
    };

    let installed_modules: HashSet<String> = sqlx::query_scalar(
        "SELECT technical_name FROM installed_modules WHERE state = 'installed'",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    let auth_user = AuthUser {
        id: tok.user_id,
        username: tok.username.clone(),
        full_name: tok.full_name.clone(),
        session_id: tok.token_id, // no session row for tokens; trace by token id
        roles: tok.roles.clone(),
        // Bearer tokens (mobile / service PAT) are first-party today; portal
        // logins use the browser session. A portal-scoped token is future work.
        contact_id: None,
        is_portal: false,
    };
    request.extensions_mut().insert(auth_user);
    request.extensions_mut().insert(tok); // ResolvedToken — scope checks
    request.extensions_mut().insert(pool.clone());
    request.extensions_mut().insert(DatabaseContext {
        db_name,
        pool,
        installed_modules,
    });

    next.run(request).await
}

// ─── Mobile / programmatic auth (/api/v1/auth/*) ──────────────────────────
// Username+password login → short access token + long refresh token, for
// first-party apps such as the SESB field-technician app. See
// `vortex_framework::mobile_auth` and migration 132. The offline field flow:
// the device works against a local queue offline (guarded by device unlock),
// and only *sync* presents the access token; when it has expired mid-shift the
// app rotates the refresh token for a new one.

/// Access-token lifetime. Short by default so a sniffed token has a small
/// window; override with `VORTEX_MOBILE_ACCESS_TTL_SECS`.
fn mobile_access_ttl() -> chrono::Duration {
    let secs = std::env::var("VORTEX_MOBILE_ACCESS_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(3600);
    chrono::Duration::seconds(secs)
}

/// Refresh-token lifetime. Size this to the worst realistic offline gap plus
/// margin; override with `VORTEX_MOBILE_REFRESH_TTL_DAYS` (default 30 days).
fn mobile_refresh_ttl() -> chrono::Duration {
    let days = std::env::var("VORTEX_MOBILE_REFRESH_TTL_DAYS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(30);
    chrono::Duration::days(days)
}

/// Resolve the target tenant DB for a mobile auth request: an explicit body
/// `database` wins, then the `X-Vortex-Database` header (the same header the
/// bearer middleware uses), then the host-based default. Keeping the header in
/// the resolution path means login/refresh name their tenant exactly the way
/// every other API call does.
async fn resolve_tenant(state: &AppState, headers: &HeaderMap, body_db: Option<&str>) -> String {
    if let Some(d) = body_db.filter(|s| !s.is_empty()) {
        return d.to_string();
    }
    if let Some(d) = headers
        .get("x-vortex-database")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        return d.to_string();
    }
    resolve_database(state, headers, None).await
}

/// Best-effort client IP (first `X-Forwarded-For` hop) and user-agent for the
/// token's audit columns.
fn request_fingerprint(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    (ip, ua)
}

/// Resolve an `Authorization: Bearer` token — a mobile **access** token first,
/// then a service `api_token` — into a full request context. `None` if there
/// is no bearer, the tenant header is malformed, the DB is down, or the token
/// is invalid/expired/revoked. Used by both the API and (as a fallback to the
/// cookie) the plugin auth middleware, so the field app reaches plugin routes
/// like `/sesb-eam/api/v1/*`.
async fn resolve_bearer(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<(
    AuthUser,
    Arc<ConnectionPool>,
    DatabaseContext,
    vortex_framework::api::ResolvedToken,
)> {
    let secret = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;

    let db_name = headers
        .get("x-vortex-database")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| state.default_db.clone());
    if !db_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let pool = state.pool_manager.get_pool(&db_name).await.ok()?;
    let db = pool.pool();

    // Mobile access token (vtxa_…) takes priority over service PATs.
    let tok = if let Some(m) = vortex_framework::mobile_auth::resolve_access(db, &secret).await {
        vortex_framework::mobile_auth::touch_last_used(db, m.token_id).await;
        vortex_framework::api::ResolvedToken {
            token_id: m.token_id,
            user_id: m.user_id,
            username: m.username,
            full_name: m.full_name,
            roles: m.roles,
            scopes: m.scopes,
        }
    } else {
        let t = vortex_framework::api::resolve_token(db, &secret).await?;
        vortex_framework::api::touch_last_used(db, t.token_id).await;
        t
    };

    let installed_modules: HashSet<String> = sqlx::query_scalar(
        "SELECT technical_name FROM installed_modules WHERE state = 'installed'",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    let auth_user = AuthUser {
        id: tok.user_id,
        username: tok.username.clone(),
        full_name: tok.full_name.clone(),
        session_id: tok.token_id,
        roles: tok.roles.clone(),
        contact_id: None,
        is_portal: false,
    };
    let db_ctx = DatabaseContext {
        db_name,
        pool: pool.clone(),
        installed_modules,
    };
    Some((auth_user, pool, db_ctx, tok))
}

#[derive(serde::Deserialize)]
struct MobileLoginBody {
    username: String,
    password: String,
    database: Option<String>,
    device_id: Option<String>,
    device_name: Option<String>,
    /// Requested capability scopes; defaults to `["write"]` so a technician
    /// can complete work orders. Policy (Cedar) still gates every call.
    scopes: Option<Vec<String>>,
    /// TOTP code, required when enrolling a *new* device for an MFA-enabled
    /// user. Omit on trusted (already-seen) devices.
    mfa_code: Option<String>,
}

/// `POST /api/v1/auth/login` — exchange credentials for an access+refresh pair.
/// Public + rate-limited. Same credential path as the web login
/// (`verify_password`), so identity and lockout rules are identical.
async fn mobile_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MobileLoginBody>,
) -> Response {
    let db_name = resolve_tenant(&state, &headers, body.database.as_deref()).await;
    if !db_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return api_error(StatusCode::BAD_REQUEST, "invalid_database", "Invalid database.");
    }
    let pool = match state.pool_manager.get_pool(&db_name).await {
        Ok(p) => p,
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "Database unavailable.",
            )
        }
    };
    let db = pool.pool();

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, password_hash, full_name, active, locked FROM users WHERE username = $1",
    )
    .bind(&body.username)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();

    let ok = user
        .as_ref()
        .map(|u| u.active && !u.locked && verify_password(&body.password, &u.password_hash))
        .unwrap_or(false);

    // Client IP for login audit attribution (best-effort).
    let (client_ip, _ua) = request_fingerprint(&headers);

    if !ok {
        // Audit the failure against the tenant chain (best-effort).
        let mut entry = AuditEntry::new(AuditAction::LoginFailure, AuditSeverity::Warning)
            .with_username(&body.username)
            .with_database(&db_name)
            .with_details(serde_json::json!({"database": db_name, "channel": "mobile"}));
        if let Some(ip) = &client_ip {
            entry = entry.with_source_ip(ip.clone());
        }
        let _ = state.audit.log(entry).await;
        return api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Invalid username or password.",
        );
    }
    let user = user.unwrap();

    // ── MFA gate ──────────────────────────────────────────────────────────
    // MFA is enforced at *device enrollment*: a brand-new device is challenged
    // (or, if the user has never set MFA up, walked through enrollment); an
    // already-seen device is trusted and skips the code, so the offline
    // silent-refresh flow is never blocked mid-shift.
    match mobile_mfa_gate(db, &user, body.device_id.as_deref(), body.mfa_code.as_deref()).await {
        MfaGate::Ok => {}
        MfaGate::Reject(resp) => {
            if matches!(&resp, MfaReject::InvalidCode) {
                let mut entry = AuditEntry::new(AuditAction::LoginFailure, AuditSeverity::Warning)
                    .with_user(vortex_common::UserId(user.id))
                    .with_username(&user.username)
                    .with_database(&db_name)
                    .with_details(serde_json::json!({"database": db_name, "channel": "mobile", "reason": "mfa"}));
                if let Some(ip) = &client_ip {
                    entry = entry.with_source_ip(ip.clone());
                }
                let _ = state.audit.log(entry).await;
            }
            return resp.into_response(&user.username);
        }
    }

    let scopes = body.scopes.unwrap_or_else(|| vec!["write".to_string()]);
    issue_mobile_session(
        &state, db, &db_name, user.id, &user.username, user.full_name.as_deref(),
        &headers, scopes, body.device_id.as_deref(), body.device_name.as_deref(),
    )
    .await
}

/// Whether a device has been seen before for this user (any token row, live or
/// not). A device_id we've issued to before is "trusted" for MFA purposes.
async fn is_known_device(db: &sqlx::PgPool, user_id: uuid::Uuid, device_id: Option<&str>) -> bool {
    let Some(dev) = device_id.filter(|s| !s.is_empty()) else {
        return false; // no device id → treat every login as a new device
    };
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM mobile_auth_token WHERE user_id = $1 AND device_id = $2)",
    )
    .bind(user_id)
    .bind(dev)
    .fetch_one(db)
    .await
    .unwrap_or(false)
}

enum MfaGate {
    Ok,
    Reject(MfaReject),
}

enum MfaReject {
    /// User is MFA-enabled, new device, and no/blank code was supplied.
    CodeRequired,
    /// A code was supplied but did not verify.
    InvalidCode,
    /// User has no MFA yet: return a provisioning secret to enroll with.
    EnrollmentRequired { secret_b32: String, username: String },
}

impl MfaReject {
    fn into_response(self, username: &str) -> Response {
        match self {
            MfaReject::CodeRequired => api_error(
                StatusCode::UNAUTHORIZED,
                "mfa_required",
                "This device needs a one-time code from your authenticator app.",
            ),
            MfaReject::InvalidCode => api_error(
                StatusCode::UNAUTHORIZED,
                "mfa_invalid_code",
                "Incorrect or expired authenticator code.",
            ),
            MfaReject::EnrollmentRequired { secret_b32, .. } => {
                let uri = vortex_security::mfa::provisioning_uri("Vortex", username, &secret_b32);
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": {
                            "code": "mfa_enrollment_required",
                            "message": "Set up your authenticator app, then confirm at /api/v1/auth/mfa/enroll."
                        },
                        "mfa": { "secret": secret_b32, "otpauth_uri": uri, "issuer": "Vortex", "account": username }
                    })),
                )
                    .into_response()
            }
        }
    }
}

/// Decide the MFA outcome for a password-authenticated user on this device.
async fn mobile_mfa_gate(
    db: &sqlx::PgPool,
    user: &UserRow,
    device_id: Option<&str>,
    mfa_code: Option<&str>,
) -> MfaGate {
    let row = sqlx::query(
        "SELECT mfa_enabled, mfa_secret FROM users WHERE id = $1",
    )
    .bind(user.id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    let mfa_enabled: bool = row.as_ref().map(|r| r.get("mfa_enabled")).unwrap_or(false);
    let stored_secret: Option<String> =
        row.as_ref().and_then(|r| r.try_get("mfa_secret").ok().flatten());

    if is_known_device(db, user.id, device_id).await {
        return MfaGate::Ok; // trusted device — no challenge
    }

    if mfa_enabled {
        // New device on an MFA user → require a valid code.
        let (Some(code), Some(enc)) = (mfa_code.filter(|s| !s.is_empty()), stored_secret) else {
            return MfaGate::Reject(MfaReject::CodeRequired);
        };
        let Some(secret) = vortex_security::mfa::open_secret(&enc) else {
            return MfaGate::Reject(MfaReject::CodeRequired);
        };
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        if vortex_security::mfa::verify(&secret, code, now) {
            MfaGate::Ok
        } else {
            MfaGate::Reject(MfaReject::InvalidCode)
        }
    } else {
        // Not enrolled yet → hand back a provisioning secret. Reuse a pending
        // one if present so re-hitting login shows the same QR until enrolled.
        let secret_b32 = match stored_secret.as_deref().and_then(vortex_security::mfa::open_secret) {
            Some(existing) => existing,
            None => {
                let fresh = vortex_security::mfa::generate_secret();
                if let Some(sealed) = vortex_security::mfa::seal_secret(&fresh) {
                    let _ = sqlx::query(
                        "UPDATE users SET mfa_secret = $2, mfa_enabled = false WHERE id = $1",
                    )
                    .bind(user.id)
                    .bind(&sealed)
                    .execute(db)
                    .await;
                }
                fresh
            }
        };
        MfaGate::Reject(MfaReject::EnrollmentRequired {
            secret_b32,
            username: user.username.clone(),
        })
    }
}

/// Issue an access+refresh pair, update last-login, audit, and return the
/// token JSON. Shared by login (post-MFA) and enrollment confirmation.
#[allow(clippy::too_many_arguments)]
async fn issue_mobile_session(
    state: &AppState,
    db: &sqlx::PgPool,
    db_name: &str,
    user_id: uuid::Uuid,
    username: &str,
    full_name: Option<&str>,
    headers: &HeaderMap,
    scopes: Vec<String>,
    device_id: Option<&str>,
    device_name: Option<&str>,
) -> Response {
    let (ip, ua) = request_fingerprint(headers);
    let ctx = vortex_framework::mobile_auth::IssueCtx {
        user_id,
        device_id,
        device_name,
        scopes: &scopes,
        access_ttl: mobile_access_ttl(),
        refresh_ttl: mobile_refresh_ttl(),
        ip: ip.as_deref(),
        user_agent: ua.as_deref(),
    };
    let pair = match vortex_framework::mobile_auth::issue_pair(db, &ctx).await {
        Ok(p) => p,
        Err(e) => {
            error!("mobile issue_pair failed: {}", e);
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "issue_failed", "Could not issue tokens.");
        }
    };

    let _ = sqlx::query(
        "UPDATE users SET last_login_at = NOW(), failed_login_attempts = 0 WHERE id = $1",
    )
    .bind(user_id)
    .execute(db)
    .await;

    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut entry = AuditEntry::new(AuditAction::LoginSuccess, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user_id))
        .with_username(username)
        .with_database(db_name)
        .with_resource("mobile_auth_token", pair.family_id.to_string())
        .with_details(serde_json::json!({
            "database": db_name, "channel": "mobile",
            "device_id": device_id, "family_id": pair.family_id,
        }));
    if let Some(ip) = &ip {
        entry = entry.with_source_ip(ip.clone());
    }
    let _ = state.audit.log(entry).await;

    let now = chrono::Utc::now();
    Json(serde_json::json!({
        "access_token": pair.access_token,
        "refresh_token": pair.refresh_token,
        "token_type": "Bearer",
        "expires_in": (pair.access_expires_at - now).num_seconds(),
        "refresh_expires_in": (pair.refresh_expires_at - now).num_seconds(),
        "database": db_name,
        "user": { "id": user_id, "username": username, "full_name": full_name, "roles": roles },
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct MobileMfaEnrollBody {
    username: String,
    password: String,
    /// TOTP code from the authenticator app the user just configured with the
    /// secret returned by `login`'s `mfa_enrollment_required` response.
    code: String,
    database: Option<String>,
    device_id: Option<String>,
    device_name: Option<String>,
    scopes: Option<Vec<String>>,
}

/// `POST /api/v1/auth/mfa/enroll` — confirm a first-time MFA setup: verify
/// password + the first TOTP code against the pending secret, flip
/// `mfa_enabled`, and issue the device's first token pair. Public + rate-limited.
async fn mobile_mfa_enroll(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MobileMfaEnrollBody>,
) -> Response {
    let db_name = resolve_tenant(&state, &headers, body.database.as_deref()).await;
    if !db_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return api_error(StatusCode::BAD_REQUEST, "invalid_database", "Invalid database.");
    }
    let pool = match state.pool_manager.get_pool(&db_name).await {
        Ok(p) => p,
        Err(_) => {
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "database_unavailable", "Database unavailable.")
        }
    };
    let db = pool.pool();

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, password_hash, full_name, active, locked FROM users WHERE username = $1",
    )
    .bind(&body.username)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    let ok = user
        .as_ref()
        .map(|u| u.active && !u.locked && verify_password(&body.password, &u.password_hash))
        .unwrap_or(false);
    if !ok {
        return api_error(StatusCode::UNAUTHORIZED, "invalid_credentials", "Invalid username or password.");
    }
    let user = user.unwrap();

    // Verify the code against the pending (or existing) secret.
    let stored: Option<String> = sqlx::query_scalar("SELECT mfa_secret FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(db)
        .await
        .ok()
        .flatten();
    let Some(secret) = stored.as_deref().and_then(vortex_security::mfa::open_secret) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "no_pending_enrollment",
            "Call /api/v1/auth/login first to obtain an enrollment secret.",
        );
    };
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    if !vortex_security::mfa::verify(&secret, body.code.trim(), now) {
        return api_error(StatusCode::UNAUTHORIZED, "mfa_invalid_code", "Incorrect or expired authenticator code.");
    }

    // Confirm enrollment, then issue the first session on this device.
    let _ = sqlx::query("UPDATE users SET mfa_enabled = true WHERE id = $1")
        .bind(user.id)
        .execute(db)
        .await;
    let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_name)
        .with_resource("users", user.id.to_string())
        .with_details(serde_json::json!({"channel": "mobile", "event": "mfa_enrolled"}));
    let _ = state.audit.log(entry).await;

    let scopes = body.scopes.unwrap_or_else(|| vec!["write".to_string()]);
    issue_mobile_session(
        &state, db, &db_name, user.id, &user.username, user.full_name.as_deref(),
        &headers, scopes, body.device_id.as_deref(), body.device_name.as_deref(),
    )
    .await
}

#[derive(serde::Deserialize)]
struct MobileRefreshBody {
    refresh_token: String,
    database: Option<String>,
}

/// `POST /api/v1/auth/refresh` — rotate a refresh token for a fresh pair.
/// Public + rate-limited. Distinct error codes let the app tell "log in again"
/// (`refresh_expired`) from "you were compromised" (`refresh_reuse_detected`).
async fn mobile_refresh(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MobileRefreshBody>,
) -> Response {
    let db_name = resolve_tenant(&state, &headers, body.database.as_deref()).await;
    if !db_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return api_error(StatusCode::BAD_REQUEST, "invalid_database", "Invalid database.");
    }
    let pool = match state.pool_manager.get_pool(&db_name).await {
        Ok(p) => p,
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "Database unavailable.",
            )
        }
    };
    let db = pool.pool();
    let (ip, ua) = request_fingerprint(&headers);

    use vortex_framework::mobile_auth::RefreshError;
    match vortex_framework::mobile_auth::rotate_refresh(
        db,
        &body.refresh_token,
        mobile_access_ttl(),
        mobile_refresh_ttl(),
        ip.as_deref(),
        ua.as_deref(),
    )
    .await
    {
        Ok(pair) => {
            let now = chrono::Utc::now();
            Json(serde_json::json!({
                "access_token": pair.access_token,
                "refresh_token": pair.refresh_token,
                "token_type": "Bearer",
                "expires_in": (pair.access_expires_at - now).num_seconds(),
                "refresh_expires_in": (pair.refresh_expires_at - now).num_seconds(),
            }))
            .into_response()
        }
        Err(RefreshError::Expired) => api_error(
            StatusCode::UNAUTHORIZED,
            "refresh_expired",
            "Refresh token expired — please log in again.",
        ),
        Err(RefreshError::Reused) => api_error(
            StatusCode::UNAUTHORIZED,
            "refresh_reuse_detected",
            "Refresh token was already used — the session has been revoked. Log in again.",
        ),
        Err(RefreshError::Invalid) => api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_refresh",
            "Invalid or revoked refresh token.",
        ),
    }
}

/// `POST /api/v1/auth/logout` — revoke the presented token's whole family
/// (this device session). Bearer-authenticated.
async fn mobile_logout(
    Db(db): Db,
    headers: HeaderMap,
    Extension(_user): Extension<AuthUser>,
) -> Response {
    if let Some(secret) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|s| s.trim())
    {
        vortex_framework::mobile_auth::revoke_by_secret(&db, secret, "logout").await;
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

/// `GET /api/v1/auth/me` — current identity, roles, scopes, and tenant.
async fn mobile_me(
    Extension(user): Extension<AuthUser>,
    Extension(tok): Extension<vortex_framework::api::ResolvedToken>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    Json(serde_json::json!({
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "roles": user.roles,
        },
        "scopes": tok.scopes,
        "database": db_ctx.db_name,
    }))
    .into_response()
}

/// `GET /api/v1/auth/devices` — active device sessions for the current user.
async fn mobile_devices(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let devices = vortex_framework::mobile_auth::list_devices(&db, user.id).await;
    let items: Vec<serde_json::Value> = devices
        .iter()
        .map(|d| {
            serde_json::json!({
                "family_id": d.family_id,
                "device_id": d.device_id,
                "device_name": d.device_name,
                "last_used_at": d.last_used_at,
                "created_at": d.created_at,
                "expires_at": d.expires_at,
            })
        })
        .collect();
    Json(serde_json::json!({ "devices": items })).into_response()
}

/// `POST /api/v1/auth/devices/{family_id}/revoke` — revoke one of the current
/// user's device sessions (lost/decommissioned device).
async fn mobile_revoke_device(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(family_id): Path<uuid::Uuid>,
) -> Response {
    let n = vortex_framework::mobile_auth::revoke_device(&db, user.id, family_id, "device_revoked").await;
    if n == 0 {
        return api_error(StatusCode::NOT_FOUND, "not_found", "No such active device session.");
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true, "revoked": n}))).into_response()
}

/// `GET /api/v1/whoami` — identity, roles, scopes, and active tenant.
async fn api_whoami(
    Extension(user): Extension<AuthUser>,
    Extension(tok): Extension<vortex_framework::api::ResolvedToken>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    Json(serde_json::json!({
        "user": { "id": user.id, "username": user.username, "full_name": user.full_name },
        "roles": user.roles,
        "scopes": tok.scopes,
        "database": db_ctx.db_name,
        "token_id": tok.token_id,
    }))
    .into_response()
}

/// `GET /api/v1/models` — the registered models a client may address.
async fn api_list_models(Db(db): Db) -> Response {
    Json(serde_json::json!({ "models": vortex_framework::api::list_models(&db).await })).into_response()
}

/// `GET /api/v1/{model}` — list records. Reserved query keys `limit`/`offset`
/// page the result; any other key is an equality filter on a registered field.
async fn api_list_records(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(model): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit = params.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(50);
    let offset = params.get("offset").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let filters: Vec<(String, String)> = params
        .iter()
        .filter(|(k, _)| k.as_str() != "limit" && k.as_str() != "offset")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    match vortex_framework::api::list_records(&db, &model, &filters, limit, offset).await {
        Ok(page) => {
            api_audit(
                &state, &db_ctx.db_name, &user,
                AuditAction::RecordViewed, AuditSeverity::Info, &model, None,
                serde_json::json!({"via": "api", "count": page.records.len(), "limit": page.limit, "offset": page.offset}),
            ).await;
            Json(serde_json::json!({
                "model": model, "records": page.records,
                "limit": page.limit, "offset": page.offset, "count": page.records.len(),
            })).into_response()
        }
        Err(e) => api_error(StatusCode::BAD_REQUEST, "list_failed", &e),
    }
}

/// `GET /api/v1/{model}/{id}` — fetch one record.
async fn api_get_record(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path((model, id)): Path<(String, uuid::Uuid)>,
) -> Response {
    match vortex_framework::api::get_record(&db, &model, id).await {
        Ok(Some(rec)) => {
            api_audit(
                &state, &db_ctx.db_name, &user,
                AuditAction::RecordViewed, AuditSeverity::Info, &model, Some(&id.to_string()),
                serde_json::json!({"via": "api"}),
            ).await;
            Json(rec).into_response()
        }
        Ok(None) => api_error(StatusCode::NOT_FOUND, "not_found", "No such record."),
        Err(e) => api_error(StatusCode::BAD_REQUEST, "get_failed", &e),
    }
}

/// Reject the request unless the token carries the `write` scope.
fn require_write(tok: &vortex_framework::api::ResolvedToken) -> Option<Response> {
    if tok.can_write() {
        None
    } else {
        Some(api_error(StatusCode::FORBIDDEN, "insufficient_scope", "Token lacks the 'write' scope."))
    }
}

/// `POST /api/v1/{model}` — create a record from a JSON body.
async fn api_create_record(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(tok): Extension<vortex_framework::api::ResolvedToken>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(model): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(resp) = require_write(&tok) {
        return resp;
    }
    match vortex_framework::api::create_record(&db, &model, &body).await {
        Ok(id) => {
            api_audit(
                &state, &db_ctx.db_name, &user,
                AuditAction::RecordCreated, AuditSeverity::Info, &model, Some(&id.to_string()),
                serde_json::json!({"via": "api"}),
            ).await;
            let rec = vortex_framework::api::get_record(&db, &model, id).await.ok().flatten();
            vortex_framework::webhooks::emit(
                &state.db, &db, &db_ctx.db_name, "record.created",
                serde_json::json!({"model": model, "id": id, "record": rec}),
            ).await;
            let _ = vortex_framework::computed_fields::store_values(&db, &model, id).await;
            let _ = vortex_framework::automation::run_rules(&db, &model, "create", id).await;
            (StatusCode::CREATED, Json(serde_json::json!({"id": id, "record": rec}))).into_response()
        }
        Err(e) => api_error(StatusCode::BAD_REQUEST, "create_failed", &e),
    }
}

/// `POST /api/v1/{model}/{id}/duplicate` — copy a record into a fresh row.
/// Identity columns are regenerated and `created_by` becomes the calling
/// user; everything else is copied verbatim (unique columns may reject the
/// copy — the DB constraint decides).
async fn api_duplicate_record(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(tok): Extension<vortex_framework::api::ResolvedToken>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path((model, id)): Path<(String, uuid::Uuid)>,
) -> Response {
    if let Some(resp) = require_write(&tok) {
        return resp;
    }
    match vortex_framework::api::duplicate_record(&db, &model, id, Some(user.id)).await {
        Ok(new_id) => {
            api_audit(
                &state, &db_ctx.db_name, &user,
                AuditAction::RecordCreated, AuditSeverity::Info, &model, Some(&new_id.to_string()),
                serde_json::json!({"via": "api", "duplicated_from": id}),
            ).await;
            let rec = vortex_framework::api::get_record(&db, &model, new_id).await.ok().flatten();
            vortex_framework::webhooks::emit(
                &state.db, &db, &db_ctx.db_name, "record.created",
                serde_json::json!({"model": model, "id": new_id, "record": rec, "duplicated_from": id}),
            ).await;
            (StatusCode::CREATED, Json(serde_json::json!({"id": new_id, "record": rec}))).into_response()
        }
        Err(e) if e == "source record not found" => {
            api_error(StatusCode::NOT_FOUND, "not_found", "No such record.")
        }
        Err(e) => api_error(StatusCode::BAD_REQUEST, "duplicate_failed", &e),
    }
}

/// `PATCH /api/v1/{model}/{id}` — partial update from a JSON body.
async fn api_update_record(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(tok): Extension<vortex_framework::api::ResolvedToken>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path((model, id)): Path<(String, uuid::Uuid)>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(resp) = require_write(&tok) {
        return resp;
    }
    match vortex_framework::api::update_record(&db, &model, id, &body).await {
        Ok(true) => {
            api_audit(
                &state, &db_ctx.db_name, &user,
                AuditAction::RecordUpdated, AuditSeverity::Info, &model, Some(&id.to_string()),
                serde_json::json!({"via": "api"}),
            ).await;
            let rec = vortex_framework::api::get_record(&db, &model, id).await.ok().flatten();
            vortex_framework::webhooks::emit(
                &state.db, &db, &db_ctx.db_name, "record.updated",
                serde_json::json!({"model": model, "id": id, "record": rec}),
            ).await;
            let _ = vortex_framework::computed_fields::store_values(&db, &model, id).await;
            let _ = vortex_framework::automation::run_rules(&db, &model, "update", id).await;
            Json(serde_json::json!({"id": id, "record": rec})).into_response()
        }
        Ok(false) => api_error(StatusCode::NOT_FOUND, "not_found", "No such record."),
        Err(e) => api_error(StatusCode::BAD_REQUEST, "update_failed", &e),
    }
}

/// `DELETE /api/v1/{model}/{id}` — remove a record.
async fn api_delete_record(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(tok): Extension<vortex_framework::api::ResolvedToken>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path((model, id)): Path<(String, uuid::Uuid)>,
) -> Response {
    if let Some(resp) = require_write(&tok) {
        return resp;
    }
    match vortex_framework::api::delete_record(&db, &model, id).await {
        Ok(true) => {
            api_audit(
                &state, &db_ctx.db_name, &user,
                AuditAction::RecordDeleted, AuditSeverity::Warning, &model, Some(&id.to_string()),
                serde_json::json!({"via": "api"}),
            ).await;
            vortex_framework::webhooks::emit(
                &state.db, &db, &db_ctx.db_name, "record.deleted",
                serde_json::json!({"model": model, "id": id}),
            ).await;
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Ok(false) => api_error(StatusCode::NOT_FOUND, "not_found", "No such record."),
        Err(e) => api_error(StatusCode::BAD_REQUEST, "delete_failed", &e),
    }
}

/// Module guard middleware for the "contacts" module.
async fn contacts_module_guard(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    module_guard_check("contacts", &state, request, next).await
}

// NOTE: the core no longer has any knowledge of vertical-specific
// middleware; plugins that need install-state gating should implement
// their own.

async fn module_guard_check(
    module_name: &str,
    _state: &AppState,
    request: Request,
    next: Next,
) -> Response {
    let is_installed = request
        .extensions()
        .get::<DatabaseContext>()
        .map(|ctx| ctx.installed_modules.contains(module_name))
        .unwrap_or(false);
    if is_installed {
        next.run(request).await
    } else {
        let path = request.uri().path().to_string();
        if path.starts_with("/api/") {
            axum::Json(serde_json::json!({
                "error": "module_not_installed",
                "module": module_name,
                "message": format!("The '{}' module is not installed", module_name)
            })).into_response()
        } else {
            Html(module_not_installed_page(module_name)).into_response()
        }
    }
}

fn module_not_installed_page(module_name: &str) -> String {
    let display_name = match module_name {
        "contacts" => "Contacts",
        _ => module_name,
    };
    format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Module Not Installed</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200 flex items-center justify-center">
<div class="card bg-base-100 shadow-xl max-w-md w-full">
<div class="card-body items-center text-center">
<div class="w-20 h-20 rounded-full bg-warning/10 flex items-center justify-center mb-4">
<svg class="w-10 h-10 text-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z"/>
</svg></div>
<h2 class="card-title text-xl">Module Not Installed</h2>
<p class="text-base-content/60 mt-2">The <strong>{display_name}</strong> module is not currently installed.</p>
<p class="text-base-content/60 text-sm mt-1">Please ask your system administrator to install it from the Modules page.</p>
<div class="card-actions mt-6 gap-3">
<a href="/modules" class="btn btn-primary">Go to Modules</a>
<a href="/home" class="btn btn-ghost">Back to Home</a>
</div></div></div></body></html>"#)
}

/// Parse the `[audit.signing]` section of `vortex.toml` and
/// resolve it to a [`SigningBackendConfig`].
///
/// Default is `SigningBackendConfig::Env` (matches Phase 0.1
/// behavior) so upgrading deployments see no change until they
/// explicitly opt into a different backend.
///
/// Layout:
///
/// ```toml
/// [audit.signing]
/// backend = "env"              # or "pkcs11"
///
/// [audit.signing.pkcs11]
/// library_path = "/usr/lib/softhsm/libsofthsm2.so"
/// token_label  = "vortex"
/// # slot        = 0             # optional, used if token_label absent
/// key_label    = "vortex-audit"
/// pin_env      = "VORTEX_HSM_PIN"
/// ```
///
/// Follows the existing `parse_db_manager_config` convention —
/// ad-hoc `toml::Value` access, tolerant of missing keys, no
/// panic on malformed config. Bad config produces a default
/// plus a warning; fatal misconfiguration is deferred to the
/// `build_signing_key` call at startup where the operator sees
/// a specific error.
pub fn parse_audit_signing_config() -> SigningBackendConfig {
    let config_str = std::fs::read_to_string("vortex.toml").unwrap_or_default();
    let config: toml::Value = config_str
        .parse::<toml::Value>()
        .unwrap_or(toml::Value::Table(Default::default()));

    let signing: Option<&toml::Value> =
        config.get("audit").and_then(|a| a.get("signing"));
    let backend = signing
        .and_then(|s| s.get("backend"))
        .and_then(|v| v.as_str())
        .unwrap_or("env");

    match backend {
        "pkcs11" => {
            let pkcs11 = signing.and_then(|s| s.get("pkcs11"));
            let library_path = pkcs11
                .and_then(|p| p.get("library_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let token_label = pkcs11
                .and_then(|p| p.get("token_label"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let slot = pkcs11
                .and_then(|p| p.get("slot"))
                .and_then(|v| v.as_integer())
                .map(|n| n as u64);
            let key_label = pkcs11
                .and_then(|p| p.get("key_label"))
                .and_then(|v| v.as_str())
                .unwrap_or("vortex-audit")
                .to_string();
            let pin_env = pkcs11
                .and_then(|p| p.get("pin_env"))
                .and_then(|v| v.as_str())
                .unwrap_or("VORTEX_HSM_PIN")
                .to_string();

            SigningBackendConfig::Pkcs11(Pkcs11Config {
                library_path,
                token_label,
                slot,
                key_label,
                pin_env,
            })
        }
        // "env" or unknown → fall back to the default Phase 0.1 path.
        _ => SigningBackendConfig::Env,
    }
}

/// Parse the [database_manager] section from vortex.toml (if present).
pub fn parse_db_manager_config() -> (bool, String, String, String, String) {
    let config_str = std::fs::read_to_string("vortex.toml").unwrap_or_default();
    let config: toml::Value = config_str.parse::<toml::Value>().unwrap_or(toml::Value::Table(Default::default()));
    let section: Option<&toml::Value> = config.get("database_manager");

    let enabled = section
        .and_then(|s: &toml::Value| s.get("enabled"))
        .and_then(|v: &toml::Value| v.as_bool())
        .unwrap_or(false);
    let master_database = section
        .and_then(|s: &toml::Value| s.get("master_database"))
        .and_then(|v: &toml::Value| v.as_str())
        .unwrap_or("vortex_master")
        .to_string();
    // Secret: env wins over the config file so vortex.toml can live in
    // version control without embedding the master credential. Accepts
    // either an $argon2 hash or (dev only) a plaintext value.
    let master_password = std::env::var("VORTEX_MASTER_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            section
                .and_then(|s: &toml::Value| s.get("master_password"))
                .and_then(|v: &toml::Value| v.as_str())
                .unwrap_or("")
                .to_string()
        });
    let db_filter = section
        .and_then(|s: &toml::Value| s.get("db_filter"))
        .and_then(|v: &toml::Value| v.as_str())
        .unwrap_or("")
        .to_string();
    let db_name_prefix = section
        .and_then(|s: &toml::Value| s.get("db_name_prefix"))
        .and_then(|v: &toml::Value| v.as_str())
        .unwrap_or("vortex_")
        .to_string();

    (enabled, master_database, master_password, db_filter, db_name_prefix)
}

/// Parse `[files]` from vortex.toml into a storage backend config.
/// Absent section → local directory "uploads" (single-tier default).
/// S3 credentials come from VORTEX_S3_ACCESS_KEY / VORTEX_S3_SECRET_KEY,
/// never from the config file.
fn parse_files_config() -> anyhow::Result<vortex_framework::files::FilesConfig> {
    use vortex_framework::files::{FilesConfig, S3Config};
    let config_str = std::fs::read_to_string("vortex.toml").unwrap_or_default();
    let config: toml::Value = config_str.parse::<toml::Value>().unwrap_or(toml::Value::Table(Default::default()));
    let section = config.get("files");
    let backend = section
        .and_then(|s| s.get("backend"))
        .and_then(|v| v.as_str())
        .unwrap_or("local");
    let str_key = |table: &str, key: &str, default: &str| -> String {
        section
            .and_then(|s| s.get(table))
            .and_then(|t| t.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_string()
    };
    match backend {
        "local" => Ok(FilesConfig::Local { path: str_key("local", "path", "uploads") }),
        "s3" => Ok(FilesConfig::S3(S3Config {
            endpoint: str_key("s3", "endpoint", ""),
            region: str_key("s3", "region", "us-east-1"),
            bucket: str_key("s3", "bucket", ""),
            path_style: section
                .and_then(|s| s.get("s3"))
                .and_then(|t| t.get("path_style"))
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            access_key: std::env::var("VORTEX_S3_ACCESS_KEY").unwrap_or_default(),
            secret_key: std::env::var("VORTEX_S3_SECRET_KEY").unwrap_or_default(),
        })),
        other => anyhow::bail!("[files] backend must be \"local\" or \"s3\", got {other:?}"),
    }
}

/// Global connection budget from `[database] max_connections` in
/// vortex.toml. This caps the SUM of every pool the manager opens
/// (primary + master + one per active tenant) — keep it below the
/// Postgres server's own `max_connections`.
fn parse_global_connection_budget() -> u32 {
    let config_str = std::fs::read_to_string("vortex.toml").unwrap_or_default();
    let config: toml::Value = config_str.parse::<toml::Value>().unwrap_or(toml::Value::Table(Default::default()));
    config
        .get("database")
        .and_then(|s| s.get("max_connections"))
        .and_then(|v| v.as_integer())
        .filter(|n| *n > 0)
        .map(|n| n as u32)
        .unwrap_or(100)
}

/// Extract the database name from a full DATABASE_URL.
fn db_name_from_url(url: &str) -> String {
    url.rsplit('/').next().unwrap_or("vortex").to_string()
}

/// Extract the base URL (without database name) from a full DATABASE_URL.
fn base_url_from_full(url: &str) -> String {
    if let Some(pos) = url.rfind('/') {
        url[..pos].to_string()
    } else {
        url.to_string()
    }
}

pub async fn run(host: String, port: u16, _workers: Option<usize>) -> Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Get database URL
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://remicle:remicle_dev_2026@localhost/remicle".to_string());

    // Parse multi-db config
    let (multi_db_enabled, master_database, master_password, db_filter, _db_name_prefix) =
        parse_db_manager_config();

    let default_db = db_name_from_url(&database_url);

    // Connect to database
    info!("Connecting to database...");
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    // Verify connection
    sqlx::query("SELECT 1").execute(&db).await?;
    info!("Database connected");

    // Seed core roles if they don't exist
    seed_core_roles(&db).await;

    // Create connection pool wrapper for plugin handlers
    let pool = Arc::new(ConnectionPool::from_pg_pool(db.clone(), &database_url));

    // ─── WORM Audit Ledger (Phase 0.1 + Phase 0.7 KMS) ─────────────────
    // Phase 0.1 shipped with an env-var-backed Ed25519 signer. Phase
    // 0.7 adds a PKCS#11 backend (SoftHSM2 for dev/CI, Thales Luna /
    // Entrust nShield / YubiHSM 2 / Utimaco CryptoServer for prod)
    // selected via the `[audit.signing]` section of vortex.toml.
    //
    // Master switch: VORTEX_AUDIT_SIGNING_MODE=disabled skips signing
    // entirely — the hash chain still provides tamper evidence, but
    // the ledger cannot attribute entries to a specific signer. Dev
    // only.
    let signing_mode = SigningMode::from_env();
    let signer: Option<Arc<dyn SigningKey>> = match signing_mode {
        SigningMode::Enabled => {
            let backend_config = parse_audit_signing_config();
            info!(
                backend = backend_config.backend_name(),
                "Audit ledger signing ENABLED — building backend"
            );
            match build_signing_key(&backend_config) {
                Ok(key) => {
                    info!(
                        backend = backend_config.backend_name(),
                        key_id = key.key_id(),
                        algorithm = key.algorithm(),
                        "Audit ledger signing key ready"
                    );
                    // Register the public half so `vortex audit verify`
                    // can validate historical entries even after the
                    // key rotates. Same upsert path for both backends —
                    // the public key source is abstracted by the
                    // SigningKey trait.
                    let key_id_owned = key.key_id().to_string();
                    let public_key = key.public_key();
                    let algorithm = key.algorithm().to_string();
                    let storage_for_register = PgAuditStorage::new(pool.clone(), None);
                    if let Err(e) = storage_for_register
                        .register_signing_key(
                            &key_id_owned,
                            &public_key,
                            &algorithm,
                            chrono::Utc::now(),
                        )
                        .await
                    {
                        warn!("audit_signing_keys upsert failed: {e}");
                    }
                    Some(key)
                }
                Err(e) => {
                    warn!(
                        backend = backend_config.backend_name(),
                        error = %e,
                        "Signing backend failed to open; falling back to unsigned \
                         chain. Set VORTEX_AUDIT_SIGNING_MODE=disabled to silence \
                         this warning in dev, or fix the backend configuration in \
                         vortex.toml before a regulated deployment."
                    );
                    None
                }
            }
        }
        SigningMode::Disabled => {
            warn!("Audit ledger signing DISABLED via VORTEX_AUDIT_SIGNING_MODE — dev only");
            None
        }
    };

    // ─── Pool Manager ─────────────────────────────────────────────────
    // Constructed before the audit storage so the multi-DB pool manager
    // can be passed to PgAuditStorage for per-tenant audit scoping.
    let pool_manager = if multi_db_enabled {
        let global_budget = parse_global_connection_budget();
        info!(
            "Pool manager: global connection budget {} across all tenant pools",
            global_budget
        );
        let config = PoolManagerConfig {
            base_url: base_url_from_full(&database_url),
            global_max_connections: global_budget,
            ..PoolManagerConfig::default()
        };
        let pm = Arc::new(DatabasePoolManager::new(config));
        // Register the default database pool
        pm.register_pool(&default_db, pool.clone()).await;
        pm
    } else {
        // Single-database mode — wrap existing pool
        Arc::new(DatabasePoolManager::single(&default_db, pool.clone()))
    };

    // ─── WORM Audit Storage ──────────────────────────────────────────
    // In multi-DB mode, the pool manager is attached so audit entries
    // with `db_name` set route to the tenant's database. System events
    // (no db_name) always go to the primary pool.
    let mut audit_storage = PgAuditStorage::new(pool.clone(), signer);
    if multi_db_enabled {
        audit_storage = audit_storage.with_pool_manager(pool_manager.clone());
        info!("Audit ledger: multi-DB scoping enabled — tenant events route to tenant databases");
    }
    let audit_storage = Arc::new(audit_storage);
    let audit = Arc::new(AuditLog::new(audit_storage).with_alert_handler(|entry| {
        error!(
            action = ?entry.action,
            user_id = ?entry.user_id,
            source_ip = ?entry.source_ip,
            "CRITICAL security event"
        );
    }));

    // ─── Policy Engine (Phase 0.2) ─────────────────────────────────────
    // Loads Cedar policies from the `policy_rules` table and builds the
    // authorizer. Policies that fail to parse are logged per-policy and
    // skipped — a bad policy should not prevent the server from starting.
    let policy_store = Arc::new(PgPolicyStore::new(db.clone()));
    let policy = match PolicyService::load(policy_store).await {
        Ok(svc) => {
            let parse_errors = svc.parse_errors().await;
            if parse_errors.is_empty() {
                info!("Policy engine loaded (0 parse errors)");
            } else {
                warn!(
                    error_count = parse_errors.len() as i64,
                    "Policy engine loaded with parse errors; some policies are inactive"
                );
                for err in &parse_errors {
                    warn!(
                        policy_id = %err.policy_db_id,
                        policy_name = %err.policy_name,
                        error = %err.error,
                        "policy parse error"
                    );
                }
            }
            Arc::new(svc)
        }
        Err(e) => {
            error!("Policy engine failed to load: {e}. Running in deny-all mode.");
            Arc::new(
                PolicyService::load(Arc::new(vortex_policy::store::PgPolicyStore::new(
                    db.clone(),
                )))
                .await
                .unwrap_or_else(|_| PolicyService::new(Arc::new(
                    vortex_policy::store::PgPolicyStore::new(db.clone()),
                ))),
            )
        }
    };

    // Set up master database if multi-db enabled
    let master_db = if multi_db_enabled {
        let base_url = base_url_from_full(&database_url);
        let master_url = format!("{}/{}", base_url, master_database);
        info!("Connecting to master database '{}'...", master_database);

        // Auto-create master database if it doesn't exist
        let admin_url = format!("{}/postgres", base_url);
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)"
        )
        .bind(&master_database)
        .fetch_one(&admin_pool)
        .await?;
        if !exists {
            info!("Creating master database '{}'...", master_database);
            let create_sql = format!("CREATE DATABASE \"{}\"", master_database);
            sqlx::query(&create_sql).execute(&admin_pool).await?;
            info!("Master database created");
        }
        drop(admin_pool);

        let mdb = PgPoolOptions::new()
            .max_connections(5)
            .connect(&master_url)
            .await?;

        // Ensure master tables exist
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS managed_databases (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(63) NOT NULL UNIQUE,
                display_name VARCHAR(255),
                state VARCHAR(20) NOT NULL DEFAULT 'active',
                demo_data BOOLEAN NOT NULL DEFAULT false,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_accessed_at TIMESTAMPTZ,
                size_bytes BIGINT,
                notes TEXT
            )"
        ).execute(&mdb).await?;
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS db_manager_config (
                key VARCHAR(100) PRIMARY KEY,
                value TEXT NOT NULL
            )"
        ).execute(&mdb).await?;

        // Auto-register the default database if not already registered
        let registered: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM managed_databases WHERE name = $1)"
        )
        .bind(&default_db)
        .fetch_one(&mdb)
        .await?;
        if !registered {
            info!("Registering default database '{}' in master registry", default_db);
            sqlx::query(
                "INSERT INTO managed_databases (name, display_name, state) VALUES ($1, $2, 'active')"
            )
            .bind(&default_db)
            .bind(&default_db)
            .execute(&mdb)
            .await?;
        }

        info!("Master database connected");
        Some(mdb)
    } else {
        None
    };

    // Load installed modules cache
    let installed: Vec<String> = sqlx::query_scalar(
        "SELECT technical_name FROM installed_modules WHERE state = 'installed'"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let installed_modules = Arc::new(RwLock::new(installed.into_iter().collect::<HashSet<String>>()));

    // ─── Plugin registry (Phase 0.3) ───────────────────────────────────
    // Register every compiled-in plugin. Each registration is feature-
    // gated so `cargo build --no-default-features` produces a core-only
    // binary with an empty registry. Core crates (vortex-framework,
    // vortex-security, vortex-orm, etc.) contain NO references to
    // plugin crates — the only place a plugin is mentioned at all is
    // right here in the composition binary.
    let mut plugin_registry = PluginRegistry::new();
    // Synthetic built-in plugins — these feed the sidebar for
    // modules whose handlers still live in this host binary (today,
    // only Contacts). They are unconditional because the handlers
    // themselves are unconditional; they carry no dep weight.
    // Contacts plugin — replaces the old ContactsBuiltinPlugin with
    // a real plugin crate that exercises every core primitive
    // (migrations, sequences, translations, scheduled actions,
    // reports, audit logging).
    plugin_registry.register(Arc::new(vortex_contacts::ContactsPlugin::new()));
    // Accounting — the double-entry base (chart of accounts, journals,
    // posting engine). Registered early: it is a primitive-style plugin
    // other modules adopt via its service API; its migrations only need
    // core tables (contacts, currencies, taxes).
    plugin_registry.register(Arc::new(vortex_accounting::AccountingPlugin::new()));
    // Inventory — a generic, always-on stock primitive (products,
    // locations, double-entry moves, on-hand) reused by maintenance
    // and procurement verticals.
    plugin_registry.register(Arc::new(vortex_inventory::InventoryPlugin::new()));
    // Purchasing — registered AFTER inventory so its migrations (which FK
    // into stock_product / stock_location) apply once those tables exist.
    plugin_registry.register(Arc::new(vortex_purchase::PurchasePlugin::new()));
    // Sales — the outbound mirror of purchasing: deliveries post stock
    // moves OUT via vortex_inventory::post_move and the invoice bridge
    // creates accounting customer invoices, so it registers after both.
    plugin_registry.register(Arc::new(vortex_sales::SalesPlugin::new()));
    // Maintenance / CMMS — registered after inventory (its migrations FK
    // into stock_product / stock_location and it consumes parts via
    // vortex_inventory::post_move).
    plugin_registry.register(Arc::new(vortex_maintenance::MaintenancePlugin::new()));
    // SESB EAM — the electrical-utility vertical. Registered AFTER
    // inventory (later phases consume the stock ledger for spare-part
    // consumption); owns the eam_* schema and specializes the CMMS base.
    plugin_registry.register(Arc::new(vortex_sesb_eam::SesbEamPlugin::new()));
    // SystemBuiltinPlugin carries host-wide scheduled actions (today:
    // the nightly WORM chain verification self-attestation). No
    // routes, no menu entries — it exists purely to feed the
    // scheduler via the standard plugin contribution path.
    plugin_registry.register(Arc::new(crate::commands::builtins::SystemBuiltinPlugin));
    #[cfg(feature = "cr")]
    plugin_registry.register(Arc::new(vortex_change::ChangeRequestPlugin::new()));
    info!(
        plugin_count = plugin_registry.len() as i64,
        plugins = ?plugin_registry.technical_names(),
        "plugin registry built"
    );

    // ─── Workflow engine (Phase 0.4) ──────────────────────────────────
    // Build the engine with audit + policy wired in, then walk every
    // registered plugin and pull in the state machines it contributes.
    // Plugins don't need to know about each other; the engine's
    // registry is the one place where every workflow lives.
    let workflow_store: Arc<dyn vortex_workflow::WorkflowStore> =
        Arc::new(vortex_workflow::PgWorkflowStore::new(db.clone()));
    let mut workflow_engine = vortex_workflow::WorkflowEngine::new(
        workflow_store,
        audit.clone(),
        policy.clone(),
    );
    for plugin in plugin_registry.plugins_iter() {
        for sm in plugin.state_machines() {
            info!(
                plugin = plugin.technical_name(),
                workflow_type = sm.workflow_type().as_str(),
                "registering state machine from plugin"
            );
            workflow_engine.register_machine(sm);
        }
    }
    let workflow = Arc::new(workflow_engine);
    let plugin_registry = Arc::new(plugin_registry);

    // ─── Auto-register compiled-in plugins (Phase 0.6b) ───────────────
    // Walk the plugin registry and upsert each plugin's metadata into
    // `installed_modules`. Newly-added plugin crates become visible to
    // `vortex module list` immediately — no SQL migration required to
    // bootstrap a new plugin. Idempotent; preserves existing install
    // state so a plugin that was already marked `installed` stays so.
    crate::commands::module_sync::sync_plugins_best_effort(&db, &plugin_registry).await;

    // ─── Scheduler (Phase 0.7) ────────────────────────────────────────
    // Collect every plugin's scheduled actions, build the scheduler's
    // handler map, and upsert definitions into `scheduled_actions`. The
    // supervisor task is spawned further down, after `state` exists,
    // because handlers are invoked with `Arc<AppState>`.
    let mut all_scheduled_actions = Vec::new();
    for plugin in plugin_registry.plugins_iter() {
        let actions = plugin.scheduled_actions();
        if !actions.is_empty() {
            info!(
                plugin = plugin.technical_name(),
                count = actions.len() as i64,
                "registering scheduled actions from plugin"
            );
            all_scheduled_actions.extend(actions);
        }
    }
    let scheduler = Arc::new(vortex_framework::scheduler::Scheduler::new(
        all_scheduled_actions,
    ));
    if let Err(e) = scheduler.sync_definitions(&db).await {
        warn!(error = %e, "failed to sync scheduled action definitions");
    }

    // ─── Report registry (Phase 0.7) ──────────────────────────────────
    // Collect every plugin's report definitions into a single
    // `ReportRegistry`. The generic HTTP route `/reports/:code` is
    // merged into the protected router below and dispatches by code
    // through this registry; direct consumers call
    // `vortex_framework::reports::render_report(state, code, params)`.
    let mut all_reports = Vec::new();
    for plugin in plugin_registry.plugins_iter() {
        let reports = plugin.reports();
        if !reports.is_empty() {
            info!(
                plugin = plugin.technical_name(),
                count = reports.len() as i64,
                "registering reports from plugin"
            );
            all_reports.extend(reports);
        }
    }
    let reports = Arc::new(vortex_framework::reports::ReportRegistry::new(all_reports));

    // Collect every plugin's printable document types (quotation, invoice, …)
    // into a single PrintDocRegistry. The /settings/print-templates UI lists
    // these; plugin print handlers render through print_layout::render_document.
    let mut all_print_docs = Vec::new();
    for plugin in plugin_registry.plugins_iter() {
        all_print_docs.extend(plugin.print_docs());
    }
    let print_docs = Arc::new(vortex_framework::print_layout::PrintDocRegistry::new(all_print_docs));

    // ─── i18n / Translations (Phase 0.7) ──────────────────────────────
    // Collect plugin-contributed translations, sync to DB, then build
    // the in-memory TranslationService. Plugin translations are upserted
    // (so code-shipped defaults can be overridden by an admin via SQL),
    // then the full table is loaded into the cache for fast t() lookups.
    let mut all_translations = Vec::new();
    for plugin in plugin_registry.plugins_iter() {
        let translations = plugin.translations();
        if !translations.is_empty() {
            info!(
                plugin = plugin.technical_name(),
                count = translations.len() as i64,
                "registering translations from plugin"
            );
            all_translations.extend(translations);
        }
    }
    if let Err(e) = vortex_framework::i18n::sync_translations(&db, &all_translations).await {
        warn!(error = %e, "failed to sync plugin translations to DB");
    }
    let i18n = match vortex_framework::i18n::TranslationService::load(&db).await {
        Ok(svc) => Arc::new(svc),
        Err(e) => {
            warn!(error = %e, "failed to load translations — using empty cache");
            Arc::new(vortex_framework::i18n::TranslationService::empty())
        }
    };

    // File/attachment storage backend ([files] in vortex.toml).
    // Fail fast on bad config: silently storing tenant files in the
    // wrong place is worse than refusing to start.
    let files_config = parse_files_config()?;
    let files = vortex_framework::files::from_config(&files_config)
        .map_err(|e| anyhow::anyhow!("file storage init failed: {e}"))?;
    info!("File storage backend: {}", files.backend_name());

    // Create app state
    let state = Arc::new(AppState {
        db,
        pool,
        pool_manager: pool_manager.clone(),
        master_db,
        master_password_hash: if master_password.is_empty() { None } else { Some(master_password) },
        db_filter: if db_filter.is_empty() { None } else { Some(db_filter) },
        multi_db: multi_db_enabled,
        default_db,
        installed_modules,
        audit,
        policy,
        workflow,
        plugin_registry: plugin_registry.clone(),
        scheduler: scheduler.clone(),
        reports: reports.clone(),
        print_docs: print_docs.clone(),
        i18n,
        files,
    });

    // Spawn the scheduler supervisor now that AppState exists.
    // `start` takes `&self` and internally `tokio::spawn`s the
    // supervisor loop, so it returns immediately. The supervisor
    // holds its own `Arc<AppState>` and runs until process shutdown.
    scheduler.start(state.clone());

    // Spawn the durable job-queue worker (mirrors the scheduler). Registers
    // the core handlers (mail.send, …); plugins can register their own here.
    {
        let mut job_registry = vortex_framework::jobs::JobRegistry::new();
        vortex_framework::jobs::register_core_handlers(&mut job_registry);
        vortex_framework::webhooks::register_handler(&mut job_registry);
        // Plugin-contributed job handlers (Plugin::register_jobs)
        for plugin in state.plugin_registry.plugins_iter() {
            plugin.register_jobs(&mut job_registry);
        }
        vortex_framework::jobs::JobWorker::new(job_registry).start(state.clone());
    }

    // Run each plugin's async startup hook. Failures are logged but do
    // not abort server startup — a single broken plugin should not take
    // the core down.
    if let Err(e) = state.plugin_registry.run_startup_hooks(&state).await {
        warn!(error = %e, "one or more plugin startup hooks failed");
    }

    // Start background pool eviction task if multi-db
    if multi_db_enabled {
        let pm = pool_manager.clone();
        let default = state.default_db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                pm.evict_idle_pools(&[default.clone()]).await;
            }
        });
    }

    // Build router
    let app = build_router(state);

    // Parse the address
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║                                                            ║");
    println!("║   \x1b[32mre\x1b[90mmicle\x1b[0m                                               ║");
    println!("║   Zero-Trust Enterprise Core                               ║");
    println!("║                                                            ║");
    println!("║   URL: http://{}:{:<24}       ║", host, port);
    println!("║   Database: Connected                                      ║");
    println!("║                                                            ║");
    println!("║   Press Ctrl+C to stop                                     ║");
    println!("║                                                            ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // Start the server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    info!("Server stopped");
    Ok(())
}

/// Build the application router
fn build_router(state: Arc<AppState>) -> Router {
    // Contacts routes are now contributed by the vortex-contacts plugin
    // via Plugin::routes(). The old inline handlers below are kept for
    // reference but no longer mounted. TODO: delete them once the plugin
    // is fully verified.

    // --- Core routes (always available) ---
    let protected_routes = Router::new()
        .route("/home", get(home_page))
        // /dashboard merged into /home (role-aware landing). Redirect
        // keeps old bookmarks and stray links working.
        .route("/dashboard", get(|| async { Redirect::to("/home") }))
        .route("/auth/logout", post(logout).get(logout))
        .route("/partials/recent-activity", get(recent_activity))
        .route("/partials/system-status", get(system_status))
        // Home partials
        .route("/partials/home/announcements", get(home_announcements_partial))
        .route("/partials/home/shortcuts", get(home_shortcuts_partial))
        .route("/partials/home/activities", get(home_activities_partial))
        .route("/partials/home/calendar", get(home_calendar_partial))
        .route("/partials/home/calendar/{year}/{month}", get(home_calendar_partial_month))
        // Announcements CRUD (admin)
        .route("/announcements", get(announcements_list))
        .route("/announcements/new", get(announcement_new))
        .route("/announcements", post(announcement_create))
        .route("/announcements/{id}/edit", get(announcement_edit))
        .route("/announcements/{id}", post(announcement_update))
        .route("/announcements/{id}/delete", post(announcement_delete))
        // Shortcuts API
        .route("/api/home/shortcuts/available", get(shortcuts_available))
        .route("/api/home/shortcuts", post(shortcut_add))
        .route("/api/home/shortcuts/{id}/delete", post(shortcut_remove))
        .route("/api/home/shortcuts/reorder", post(shortcuts_reorder))
        // User management
        .route("/users", get(users_list))
        .route("/users/new", get(users_new_form))
        .route("/users", post(users_create))
        .route("/users/{id}", get(users_edit_form))
        .route("/users/{id}", post(users_update))
        .route("/users/{id}/toggle", post(users_toggle_active))
        .route("/users/{id}/unlock", post(users_unlock))
        // Access control management (admin only)
        .route("/admin/access", get(access_control_page))
        .route("/admin/access/models/new", get(access_model_new_page))
        .route("/admin/access/models", post(access_model_create))
        .route("/admin/access/models/{id}/edit", get(access_model_edit_page))
        .route("/admin/access/models/{id}", post(access_model_update))
        .route("/admin/access/rules/new", get(access_rule_new_page))
        .route("/admin/access/rules", post(access_rule_create))
        .route("/admin/access/rules/{id}/edit", get(access_rule_edit_page))
        .route("/admin/access/rules/{id}", post(access_rule_update))
        .route("/admin/access/fields/new", get(access_field_new_page))
        .route("/admin/access/fields", post(access_field_create))
        .route("/admin/access/fields/{id}/edit", get(access_field_edit_page))
        .route("/admin/access/fields/{id}", post(access_field_update))
        // Module management
        .route("/modules", get(modules_list))
        .route("/modules/refresh", post(modules_refresh))
        .route("/modules/app/{id}", get(modules_detail))
        .route("/modules/{filter}", get(modules_list_with_filter))
        .route("/modules/{id}/install", post(module_install))
        .route("/modules/{id}/uninstall", post(module_uninstall))
        .route("/modules/{id}/upgrade", post(module_upgrade))
        // Generic model views
        .route("/list/{model}", get(generic_list_view))
        .route("/kanban/{model}", get(generic_kanban_view))
        .route("/graph/{model}", get(generic_graph_view))
        .route("/calendar/{model}", get(generic_calendar_view))
        .route("/pivot/{model}", get(generic_pivot_view))
        .route("/pivot/{model}/data", get(generic_pivot_data))
        .route("/pivot/{model}/values", get(generic_pivot_values))
        // Saved analytic views (Initiative #4)
        .route("/views/save", post(saved_view_save))
        .route("/views/{id}/delete", post(saved_view_delete))
        // Saved filters API
        .route("/api/filters/{model}", get(get_filters))
        .route("/api/filters/{model}", post(save_filter))
        // Sequences API
        .route("/api/sequence/{code}", get(get_next_sequence))
        // Attachments API
        .route("/api/attachments/{model}/{id}", get(list_attachments))
        .route("/api/attachments/{model}/{id}", post(upload_attachment))
        .route("/attachments/{id}", get(download_attachment))
        .route("/attachments/{id}", delete(delete_attachment))
        // Chatter partials
        .route("/partials/chatter/{model}/{record_id}", get(chatter_partial))
        .route("/api/chatter/{model}/{record_id}/messages", post(chatter_post_message))
        .route("/api/chatter/{model}/{record_id}/activities", post(chatter_post_activity))
        .route("/api/chatter/{model}/{record_id}/activities/{activity_id}/complete", post(chatter_complete_activity))
        .route("/api/chatter/{model}/{record_id}/activities/{activity_id}/complete-and-schedule", post(chatter_complete_and_schedule))
        // Chatter attachments
        .route("/api/chatter/{model}/{record_id}/attachments", post(chatter_upload_attachment))
        .route("/api/chatter/attachments/{id}/download", get(chatter_download_attachment))
        .route("/api/chatter/attachments/{id}", delete(chatter_delete_attachment))
        // Activity types management
        .route("/settings", get(settings_index))
        .route("/audit", get(audit_log_page))
        .route("/notifications", get(notifications_page))
        .route("/settings/custom-fields", get(custom_fields_list))
        .route("/settings/custom-fields", post(custom_field_create))
        .route("/settings/custom-fields/delete", post(custom_field_delete))
        .route("/settings/custom-fields/reorder", post(custom_field_reorder))
        .route("/settings/automation-rules", get(automation_rules_list))
        .route("/settings/automation-rules", post(automation_rule_create))
        .route("/settings/automation-rules/delete", post(automation_rule_delete))
        .route("/settings/computed-fields", get(computed_fields_list))
        .route("/settings/computed-fields", post(computed_field_create))
        .route("/settings/computed-fields/delete", post(computed_field_delete))
        .route("/dashboards", get(dashboards_index).post(dashboard_create))
        .route("/dashboards/{id}", get(dashboard_view))
        .route("/dashboards/{id}/delete", post(dashboard_delete))
        .route("/dashboards/{id}/widget", post(dashboard_widget_create))
        .route("/dashboards/widget/{id}/delete", post(dashboard_widget_delete))
        .route("/settings/activity-types", get(activity_types_list))
        .route("/settings/activity-types", post(activity_type_create))
        .route("/settings/activity-types/{id}", get(activity_type_edit))
        .route("/settings/activity-types/{id}", post(activity_type_update))
        .route("/settings/activity-types/{id}/delete", post(activity_type_delete))
        // Sequences management
        .route("/settings/sequences", get(sequences_list))
        .route("/settings/sequences", post(sequence_create))
        .route("/settings/sequences/{id}", get(sequence_edit))
        .route("/settings/sequences/{id}", post(sequence_update))
        // Cron Jobs management
        .route("/settings/cron", get(cron_list))
        .route("/settings/cron", post(cron_create))
        .route("/settings/cron/{id}", get(cron_edit))
        .route("/settings/cron/{id}", post(cron_update))
        .route("/settings/cron/{id}/toggle", post(cron_toggle))
        .route("/settings/cron/{id}/run", post(cron_run_now))
        // Reports
        .route("/report/{model}/{id}", get(report_single))
        .route("/report/{model}", get(report_list))
        .route("/settings/reports", get(reports_list))
        .route("/settings/reports", post(report_create))
        .route("/settings/reports/{id}", get(report_edit))
        .route("/settings/reports/{id}", post(report_update))
        .route("/settings/reports/{id}/delete", post(report_delete))
        .route("/settings/reports/{id}/columns", post(report_column_add))
        .route("/settings/reports/{id}/columns/{cid}/delete", post(report_column_delete))
        .route("/settings/reports/{id}/filters", post(report_filter_add))
        .route("/settings/reports/{id}/filters/{fid}/delete", post(report_filter_delete))
        // User report hub + runner
        .route("/reports", get(reports_hub))
        .route("/reports/run/{id}", get(report_run))
        .route("/reports/queue/{id}", post(report_queue))
        .route("/reports/runs", get(report_runs_page))
        .route("/reports/runs/{id}/download", get(report_run_download))
        .route("/reports/runs/{id}/retry", post(report_run_retry))
        // Localization master data (countries / states)
        .route("/settings/countries", get(countries_list))
        .route("/settings/countries", post(country_create))
        .route("/settings/countries/{id}", get(country_edit))
        .route("/settings/countries/{id}", post(country_update))
        .route("/settings/states", get(states_list))
        .route("/settings/states", post(state_create))
        .route("/settings/states/{id}", get(state_edit))
        .route("/settings/states/{id}", post(state_update))
        // Stages (user-managed status-bar stages)
        .route("/settings/stages", get(stages_list))
        .route("/settings/stages", post(stage_create))
        .route("/settings/stages/{id}", get(stage_edit))
        .route("/settings/stages/{id}", post(stage_update))
        .route("/settings/stages/{id}/delete", post(stage_delete))
        // Stage buttons (role-gated transitions)
        .route("/settings/stage-buttons", get(stage_buttons_list))
        .route("/settings/stage-buttons", post(stage_button_create))
        .route("/settings/stage-buttons/{id}", get(stage_button_edit))
        .route("/settings/stage-buttons/{id}", post(stage_button_update))
        .route("/settings/stage-buttons/{id}/delete", post(stage_button_delete))
        // Approval rules (steps attached to stage buttons)
        .route("/settings/approval-rules", get(approval_rules_list))
        .route("/settings/approval-rules", post(approval_rule_create))
        .route("/settings/approval-rules/{id}/delete", post(approval_rule_delete))
        // Email / SMTP servers (per-tenant outbound mail)
        .route("/settings/email", get(email_servers_list))
        .route("/settings/email", post(email_server_create))
        .route("/settings/email/{id}", get(email_server_edit))
        .route("/settings/email/{id}", post(email_server_update))
        .route("/settings/email/{id}/delete", post(email_server_delete))
        .route("/settings/email/{id}/test", post(email_server_test))
        // Background job queue (durable, admin)
        .route("/settings/jobs", get(jobs_list))
        .route("/settings/jobs/{id}/retry", post(job_retry))
        .route("/settings/jobs/{id}/cancel", post(job_cancel))
        // API tokens (bearer credentials for the public REST API, admin)
        .route("/settings/api-tokens", get(api_tokens_list))
        .route("/settings/api-tokens", post(api_token_create))
        .route("/settings/api-tokens/{id}/revoke", post(api_token_revoke))
        // Portal user provisioning (admin-gated in-handler)
        .route("/settings/portal-users", get(portal_users_list))
        .route("/settings/portal-users/invite", post(portal_user_invite))
        .route("/settings/portal-users/contact/{id}", get(portal_user_for_contact))
        .route("/settings/portal-users/{id}/revoke", post(portal_user_revoke))
        .route("/settings/portal-users/{id}/resend", post(portal_user_resend))
        // Webhooks (outbound event subscriptions, admin)
        .route("/settings/webhooks", get(webhooks_list))
        .route("/settings/webhooks", post(webhook_create))
        .route("/settings/webhooks/{id}", get(webhook_edit))
        .route("/settings/webhooks/{id}", post(webhook_update))
        .route("/settings/webhooks/{id}/delete", post(webhook_delete))
        .route("/settings/webhooks/{id}/test", post(webhook_test))
        // Print layout designer — document branding + per-document templates
        .route("/settings/document-layout", get(document_layout_page))
        .route("/settings/document-layout", post(document_layout_save))
        .route("/settings/document-layout/logo", post(document_layout_logo))
        .route("/settings/print-templates", get(print_templates_list))
        .route("/settings/print-templates/{doc_type}", get(print_template_edit))
        .route("/settings/print-templates/{doc_type}", post(print_template_save))
        .route("/settings/print-templates/{doc_type}/preview", post(print_template_preview))
        .route("/settings/print-templates/{doc_type}/visual", post(print_template_visual_save))
        .route("/settings/print-templates/{doc_type}/visual/preview", post(print_template_visual_preview))
        .route("/settings/company-logo", get(serve_company_logo))
        // Approvals (generic, cross-module inbox + decisions)
        .route("/approvals", get(approvals_inbox))
        .route("/approvals/{id}/approve", post(approval_approve))
        .route("/approvals/{id}/reject", post(approval_reject))
        // Dynamic Form View
        .route("/form/{model}/new", get(dynamic_form_new))
        .route("/form/{model}", post(dynamic_form_create))
        .route("/form/{model}/{id}", get(dynamic_form_edit))
        .route("/form/{model}/{id}", post(dynamic_form_update))
        // API endpoints
        .route("/api/notifications", get(api_notifications))
        .route("/api/countries", get(api_countries))
        .route("/api/states/{country_id}", get(api_states))
        // Many2One typeahead suggestion feed (signed descriptor)
        .route("/api/lookup", get(api_lookup))
        ;

    // ─── Plugin-contributed routes (Phase 0.3) ────────────────────
    // Every registered plugin contributes a Router fragment via
    // `Plugin::routes()` and a list of stateless sub-services via
    // `Plugin::nested_services()`. Merge/nest both into the protected
    // routes before the auth middleware wraps the whole tree.
    let mut protected_routes = state.plugin_registry.build_router(protected_routes);
    for plugin in state.plugin_registry.plugins_iter() {
        for (prefix, router) in plugin.nested_services() {
            protected_routes = protected_routes.nest_service(&prefix, router);
        }
    }
    // ─── Reports endpoint (Phase 0.7) ─────────────────────────────
    // The generic `/reports/:code` route dispatches by code through
    // the central `ReportRegistry` and handles format negotiation,
    // audit logging, and response assembly. Plugins do not need to
    // register their own report routes — declaring a `ReportDef` in
    // `Plugin::reports()` is enough.
    let protected_routes =
        protected_routes.merge(vortex_framework::reports::reports_routes());
    let protected_routes = protected_routes
        // Auth middleware wraps everything
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // ─── Plugin public portal routes ──────────────────────────────
    // `Plugin::public_routes()` — anonymous surface. Each plugin's
    // router is wrapped in its module gate (404 unless installed for
    // the tenant), then the merged set gets the public context
    // middleware (Host-based tenant resolution + DatabaseContext).
    // Layer order: context outermost, gate inside it, handler last.
    let mut public_plugin_routes = Router::new();
    for plugin in state.plugin_registry.plugins_iter() {
        let plugin_name = plugin.technical_name();
        let public = plugin.public_routes();
        // route_layer on an empty router panics — most plugins have
        // no public surface, so skip them.
        if !public.has_routes() {
            continue;
        }
        let gated = public.route_layer(middleware::from_fn(
            move |request: Request, next: Next| public_module_gate(plugin_name, request, next),
        ));
        public_plugin_routes = public_plugin_routes.merge(gated);
    }
    let public_plugin_routes = if public_plugin_routes.has_routes() {
        public_plugin_routes.route_layer(middleware::from_fn_with_state(
            state.clone(),
            public_context_middleware,
        ))
    } else {
        public_plugin_routes
    };

    // Login-specific rate limiter: 5 attempts per 60 seconds per IP
    let login_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: 5,
        window: std::time::Duration::from_secs(60),
        per_user: false,
    });

    // Rate-limited login route. The `Extension` must be the outermost layer
    // (added last) so the rate-limit middleware can read the `RateLimiter`
    // from request extensions — otherwise the limiter is never found and the
    // brute-force guard silently no-ops.
    let login_routes = Router::new()
        .route("/auth/login", post(login_submit))
        .layer(middleware::from_fn(vortex_server::middleware::rate_limit::rate_limit_middleware))
        .layer(Extension(login_limiter));

    // Public, rate-limited mobile auth: credential login + refresh rotation.
    // These MUST stay outside `api_auth_middleware` (they mint the very token
    // that middleware requires). Static paths outrank `/api/v1/{model}`.
    let mobile_auth_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: 10,
        window: std::time::Duration::from_secs(60),
        per_user: false,
    });
    let mobile_auth_public = Router::new()
        .route("/api/v1/auth/login", post(mobile_login))
        .route("/api/v1/auth/mfa/enroll", post(mobile_mfa_enroll))
        .route("/api/v1/auth/refresh", post(mobile_refresh))
        // Order matters: the LAST `.layer` is the outermost. The rate-limit
        // middleware reads the `RateLimiter` from request extensions, so the
        // `Extension` must wrap (be outer to) it — hence added last.
        .layer(middleware::from_fn(vortex_server::middleware::rate_limit::rate_limit_middleware))
        .layer(Extension(mobile_auth_limiter));

    // ─── Public REST API (Phase: developer platform) ──────────────
    // Bearer-token authenticated, JSON in/out, separate from the cookie
    // tree. Static segments (`whoami`, `models`) take precedence over the
    // `{model}` parameter in the router, so they are not shadowed.
    let api_routes = Router::new()
        // Bearer-authenticated mobile auth: logout, identity, device sessions.
        .route("/api/v1/auth/logout", post(mobile_logout))
        .route("/api/v1/auth/me", get(mobile_me))
        .route("/api/v1/auth/devices", get(mobile_devices))
        .route("/api/v1/auth/devices/{family_id}/revoke", post(mobile_revoke_device))
        .route("/api/v1/whoami", get(api_whoami))
        .route("/api/v1/models", get(api_list_models))
        .route("/api/v1/{model}", get(api_list_records).post(api_create_record))
        .route(
            "/api/v1/{model}/{id}",
            get(api_get_record).patch(api_update_record).delete(api_delete_record),
        )
        .route("/api/v1/{model}/{id}/duplicate", post(api_duplicate_record))
        .route_layer(middleware::from_fn_with_state(state.clone(), api_auth_middleware));

    // ─── External portal (/portal/*) ──────────────────────────────
    // Protected surface: only `is_portal` users, guarded by
    // `portal_auth_middleware`. Separate from the internal tree, whose
    // `auth_middleware` bounces portal users away.
    let portal_protected = Router::new()
        .route("/portal", get(portal_home))
        .route("/portal/invoices", get(portal_invoices))
        .route("/portal/invoices/{id}", get(portal_invoice_detail))
        .route("/portal/orders", get(portal_orders))
        .route("/portal/statement", get(portal_statement))
        .route("/portal/logout", post(portal_logout))
        .route_layer(middleware::from_fn_with_state(state.clone(), portal_auth_middleware));

    // Public portal login (pre-auth), rate-limited like the staff login.
    let portal_login_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: 5,
        window: std::time::Duration::from_secs(60),
        per_user: false,
    });
    let portal_public = Router::new()
        .route("/portal/login", get(portal_login_page).post(portal_login_submit))
        // Invite acceptance (set-password) is pre-auth, like login.
        .route("/portal/invite/{token}", get(portal_invite_page).post(portal_invite_submit))
        .layer(middleware::from_fn(vortex_server::middleware::rate_limit::rate_limit_middleware))
        .layer(Extension(portal_login_limiter));

    // Public routes - no authentication required
    Router::new()
        // Health check
        .route("/health", get(health_check))

        // Static files
        .nest_service("/static", ServeDir::new("crates/vortex-cli/static")
            .fallback(ServeDir::new("crates/vortex-server/static")
            .fallback(ServeDir::new("static"))))

        // Auth pages (public)
        .route("/", get(|| async { Redirect::to("/login") }))
        .route("/login", get(login_page))
        .merge(login_routes)

        // Public mobile auth (login + refresh), rate-limited
        .merge(mobile_auth_public)

        // Plugin public portal routes (anonymous, tenant-resolved,
        // module-gated) — Plugin::public_routes()
        .merge(public_plugin_routes)

        // Database manager (public, master-password protected)
        .nest("/web/database/manager", super::db_manager::db_manager_routes())

        // Merge protected routes
        .merge(protected_routes)

        // External portal: public login + protected self-service tree
        .merge(portal_public)
        .merge(portal_protected)

        // Merge the bearer-authenticated REST API
        .merge(api_routes)

        // Add state
        .with_state(state)
        // Security headers on all responses (outermost layer)
        .layer(middleware::from_fn(security_headers_middleware))
}

async fn health_check(State(state): State<Arc<AppState>>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, "OK").into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "Database unavailable").into_response(),
    }
}

async fn api_notifications(
    Extension(user): Extension<AuthUser>,
) -> axum::Json<serde_json::Value> {
    // For now, return demo notifications
    // TODO: Fetch from database when notifications table exists
    axum::Json(serde_json::json!({
        "notifications": [
            {
                "id": 1,
                "type": "task",
                "message": "Welcome to Remicle! Your account is ready.",
                "time": "Just now",
                "unread": true
            }
        ],
        "count": 1,
        "statusMessage": format!("Welcome back, {}!", user.username)
    }))
}

async fn login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Html<String> {
    // Host-scoped: on gaia.vortex.com this is just ["gaia"], so the
    // picker disappears and other tenants' names never reach the page.
    let databases = login_databases(&state, &headers).await;
    let show_selector = databases.len() > 1;

    let db_selector_html = if show_selector {
        let options: String = databases.iter().map(|db| {
            format!(r#"<option value="{0}">{0}</option>"#, html_escape(db))
        }).collect();
        format!(r#"
                    <div class="form-control mb-4">
                        <label class="label">
                            <span class="label-text">Database</span>
                        </label>
                        <select name="database" class="select select-bordered">
                            {options}
                        </select>
                    </div>"#)
    } else {
        String::new()
    };

    let template = include_str!("../../templates/login_standalone.html");
    // Inject database selector before the username field
    let html = template.replace(
        r#"<div class="form-control mb-4">
                        <label class="label">
                            <span class="label-text">Username</span>"#,
        &format!(r#"{db_selector_html}
                    <div class="form-control mb-4">
                        <label class="label">
                            <span class="label-text">Username</span>"#),
    );
    Html(html)
}

/// List active database names from the master registry.
async fn list_active_databases(master_db: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT name FROM managed_databases WHERE state = 'active' ORDER BY name"
    )
    .fetch_all(master_db)
    .await
    .unwrap_or_default()
}

/// Request host, lowercased, with any `:port` suffix (or IPv6 brackets)
/// stripped. `None` when the Host header is absent or empty.
fn request_host(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::HOST)?.to_str().ok()?.trim();
    let host = if let Some(v6) = raw.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        raw.split(':').next().unwrap_or("")
    };
    let host = host.to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Loopback-style hosts get ops treatment under `db_filter`: the full
/// database picker instead of host-locked tenant resolution. Public
/// traffic always arrives through the reverse proxy with a real domain,
/// so anything the proxy would never send counts as local.
fn is_local_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1" || host.ends_with(".localhost")
}

/// Databases out of `databases` that `host` selects under the `db_filter`
/// regex. `%h` expands to the host's first DNS label and `%d` to the full
/// host, both regex-escaped — so `"^%h$"` maps gaia.vortex.com → database
/// `gaia`, and `"^vortex_%h$"` maps it to `vortex_gaia` (matching a
/// `db_name_prefix`). An unparseable filter selects nothing.
fn host_filtered_databases(filter: &str, host: &str, databases: &[String]) -> Vec<String> {
    let subdomain = host.split('.').next().unwrap_or("");
    let pattern = filter
        .replace("%h", &regex::escape(subdomain))
        .replace("%d", &regex::escape(host));
    match regex::Regex::new(&pattern) {
        Ok(re) => databases.iter().filter(|d| re.is_match(d)).cloned().collect(),
        Err(e) => {
            warn!("db_filter expanded to invalid regex {:?}: {}", pattern, e);
            Vec::new()
        }
    }
}

/// Databases this request is allowed to log into, which is also exactly
/// what the login page may list — tenant names must not leak across
/// subdomains.
///
/// - `db_filter` set and the host matches ≥1 active database → only the
///   matches (usually one; the picker disappears and login is host-locked).
/// - `db_filter` set, no match, loopback host → every active database
///   (ops/testing access on the box itself).
/// - `db_filter` set, no match, public host → the default database only.
/// - no `db_filter` → every active database (legacy behavior).
async fn login_databases(state: &AppState, headers: &HeaderMap) -> Vec<String> {
    let all = match (&state.master_db, state.multi_db) {
        (Some(master), true) => list_active_databases(master).await,
        _ => vec![state.default_db.clone()],
    };
    let Some(filter) = &state.db_filter else {
        return all;
    };
    if let Some(host) = request_host(headers) {
        let matches = host_filtered_databases(filter, &host, &all);
        if !matches.is_empty() {
            return matches;
        }
        if is_local_host(&host) {
            return all;
        }
    }
    vec![state.default_db.clone()]
}

/// Resolve which database to use for a login attempt. The form value is
/// honored only when it's in the host's allowed set, so a crafted POST
/// can't log into another tenant through this host; with `db_filter`
/// configured, an unmatched public host falls back to the default
/// database instead of erroring on a garbage pool name.
async fn resolve_database(state: &AppState, headers: &HeaderMap, form_db: Option<&str>) -> String {
    let allowed = login_databases(state, headers).await;
    if let Some(db) = form_db.filter(|s| !s.is_empty()) {
        if allowed.iter().any(|d| d == db) {
            return db.to_string();
        }
    }
    // Host-locked: the (first) match is the tenant. On loopback the
    // allowed set is the full list, where "no form choice" keeps
    // meaning the default database.
    if state.db_filter.is_some() {
        if let Some(host) = request_host(headers) {
            if !is_local_host(&host) {
                if let Some(first) = allowed.first() {
                    return first.clone();
                }
            }
        }
    }
    state.default_db.clone()
}

#[derive(serde::Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    database: Option<String>,
}

async fn login_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // Client IP (best-effort, first X-Forwarded-For hop) for the login audit —
    // so successful and failed logins are attributable to a source address.
    let (client_ip, _ua) = request_fingerprint(&headers);

    // Resolve target database
    let db_name = resolve_database(&state, &headers, form.database.as_deref()).await;

    // Get pool for that database
    let pool = match state.pool_manager.get_pool(&db_name).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to get pool for database '{}': {}", db_name, e);
            return error_response("Database unavailable");
        }
    };
    let db = pool.pool().clone();

    // Query user from database
    let user = sqlx::query_as::<_, UserRow>(
        r#"
        SELECT id, username, password_hash, full_name, active, locked
        FROM users
        WHERE username = $1
        "#
    )
    .bind(&form.username)
    .fetch_optional(&db)
    .await;

    match user {
        Ok(Some(user)) => {
            // Check if user is active and not locked
            if !user.active {
                return error_response("Account is disabled");
            }
            if user.locked {
                return error_response("Account is locked");
            }

            // Verify password
            if verify_password(&form.password, &user.password_hash) {
                // Create session
                let session_token = generate_session_token();
                let token_hash = hash_token(&session_token);

                // Store session in database
                let session_result = sqlx::query(
                    r#"
                    INSERT INTO sessions (user_id, token_hash, expires_at, ip_address)
                    VALUES ($1, $2, NOW() + INTERVAL '30 minutes', NULL)
                    "#
                )
                .bind(&user.id)
                .bind(&token_hash)
                .execute(&db)
                .await;

                if let Err(e) = session_result {
                    error!("Failed to create session: {}", e);
                    return error_response("Login failed");
                }

                // Update last login
                let _ = sqlx::query(
                    "UPDATE users SET last_login_at = NOW(), failed_login_attempts = 0 WHERE id = $1"
                )
                .bind(&user.id)
                .execute(&db)
                .await;

                // Log successful login through the WORM ledger.
                //
                // Multi-DB: `.with_database(&db_name)` routes the audit
                // entry to the tenant's database so each tenant's audit
                // chain is self-contained. In single-DB mode, db_name
                // matches the primary and the write goes there anyway.
                let mut audit_entry = AuditEntry::new(
                    AuditAction::LoginSuccess,
                    AuditSeverity::Info,
                )
                .with_user(vortex_common::UserId(user.id))
                .with_username(&user.username)
                .with_database(&db_name)
                .with_resource("session", user.id.to_string())
                .with_details(serde_json::json!({
                    "database": db_name,
                    "session_id": token_hash,
                }));
                if let Some(ip) = &client_ip {
                    audit_entry = audit_entry.with_source_ip(ip.clone());
                }
                if let Err(e) = state.audit.log(audit_entry).await {
                    error!("WORM audit write failed for LoginSuccess: {}", e);
                }

                // Return success with session cookie (db_name|token format for multi-db)
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::SET_COOKIE,
                    format!(
                        "session={}|{}; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800",
                        db_name, session_token
                    )
                    .parse()
                    .unwrap(),
                );
                headers.insert("HX-Redirect", "/home".parse().unwrap());
                (StatusCode::OK, headers, Html("")).into_response()
            } else {
                // Increment failed attempts
                let _ = sqlx::query(
                    "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1"
                )
                .bind(&user.id)
                .execute(&db)
                .await;

                // Log failed login — WORM ledger.
                let mut audit_entry = AuditEntry::new(
                    AuditAction::LoginFailure,
                    AuditSeverity::Warning,
                )
                .with_user(vortex_common::UserId(user.id))
                .with_username(&user.username)
                .with_resource("session", user.id.to_string())
                .with_error("invalid_password")
                .with_details(serde_json::json!({
                    "reason": "invalid_password",
                    "database": db_name,
                }));
                if let Some(ip) = &client_ip {
                    audit_entry = audit_entry.with_source_ip(ip.clone());
                }
                if let Err(e) = state.audit.log(audit_entry).await {
                    error!("WORM audit write failed for LoginFailure: {}", e);
                }

                error_response("Invalid username or password")
            }
        }
        Ok(None) => {
            // Log failed login attempt for unknown user — WORM ledger.
            let mut audit_entry = AuditEntry::new(
                AuditAction::LoginFailure,
                AuditSeverity::Warning,
            )
            .with_username(&form.username)
            .with_resource("session", "unknown")
            .with_error("user_not_found")
            .with_details(serde_json::json!({
                "reason": "user_not_found",
                "database": db_name,
            }));
            if let Some(ip) = &client_ip {
                audit_entry = audit_entry.with_source_ip(ip.clone());
            }
            if let Err(e) = state.audit.log(audit_entry).await {
                error!("WORM audit write failed for unknown-user LoginFailure: {}", e);
            }

            error_response("Invalid username or password")
        }
        Err(e) => {
            error!("Database error during login: {}", e);
            error_response("Login failed")
        }
    }
}

// ============================================================================
// External customer/vendor portal — /portal/*
// ============================================================================
//
// A self-service surface for **portal users** (`users.is_portal = true`, bound
// to a `contacts` row via `users.contact_id`). It is a hard-isolated tree:
//
//   * `portal_auth_middleware` guards every `/portal/*` page and admits ONLY
//     portal users; the internal `auth_middleware` conversely rejects them.
//   * Every query is scoped by the partner id derived from the **session**
//     (`AuthUser::portal_contact_id`), never a request parameter — so a portal
//     user can only ever see their own partner's documents, and record views
//     re-check ownership (`WHERE id = $1 AND partner_id = $2`).
//
// MVP surfaces: landing, my invoices (+ detail), my orders, my statement
// (open items / ageing). PDF download and a vendor view are follow-ups.

fn portal_money(v: f64) -> String {
    // Group thousands with commas, two decimals. Small, dependency-free.
    let neg = v < 0.0;
    let s = format!("{:.2}", v.abs());
    let (int, frac) = s.split_once('.').unwrap_or((s.as_str(), "00"));
    let mut grouped = String::new();
    let bytes = int.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(*b as char);
    }
    format!("{}{}.{}", if neg { "-" } else { "" }, grouped, frac)
}

/// The mobile-first portal chrome. Self-contained (vendored daisyUI, like the
/// rest of the served pages); no internal sidebar or admin surfaces.
fn portal_shell(title: &str, who: &str, active: &str, body: &str) -> String {
    use vortex_framework::ui::html_escape;
    let nav = |href: &str, id: &str, label: &str| -> String {
        let cls = if id == active { "font-semibold text-base-content" } else { "text-base-content/60" };
        format!(r#"<a href="{href}" class="{cls} hover:text-base-content whitespace-nowrap">{label}</a>"#)
    };
    format!(
        r#"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<title>{title} · Portal</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vendor/tailwind.js"></script>
<style>
body {{ background: oklch(var(--b2)); color: oklch(var(--bc)); }}
.pbar {{ background: oklch(var(--b1)); border-bottom: 1px solid oklch(var(--b3)); position: sticky; top: 0; z-index: 40; }}
.pcard {{ background: oklch(var(--b1)); border: 1px solid oklch(var(--b3)); border-radius: .6rem; }}
table.ptbl {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
table.ptbl th, table.ptbl td {{ padding: .5rem .6rem; border-bottom: 1px solid oklch(var(--b3)); text-align: left; }}
table.ptbl td.num, table.ptbl th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
</style></head><body class="min-h-screen">
<nav class="pbar px-4 py-3 flex items-center justify-between gap-4">
  <a href="/portal" class="text-lg font-bold"><span style="color:#8BC53F">re</span><span class="text-base-content/60">micle</span> <span class="font-normal text-sm text-base-content/50">Portal</span></a>
  <div class="flex items-center gap-4 text-sm overflow-x-auto">
    {home}{invoices}{orders}{statement}
    <span class="text-base-content/40 hidden sm:inline">|</span>
    <span class="text-base-content/70 hidden sm:inline">{who}</span>
    <form method="post" action="/portal/logout" class="inline"><button class="text-error hover:underline">Sign out</button></form>
  </div>
</nav>
<main class="max-w-4xl mx-auto p-4 md:p-6">{body}</main>
</body></html>"#,
        title = html_escape(title),
        who = html_escape(who),
        home = nav("/portal", "home", "Home"),
        invoices = nav("/portal/invoices", "invoices", "Invoices"),
        orders = nav("/portal/orders", "orders", "Orders"),
        statement = nav("/portal/statement", "statement", "Statement"),
        body = body,
    )
}

#[derive(serde::Deserialize)]
struct PortalLoginForm {
    username: String,
    password: String,
    database: Option<String>,
}

/// Standalone portal login page (no shell nav — pre-auth). `err` shows a
/// validation message when re-rendered after a failed attempt.
fn portal_login_html(err: Option<&str>) -> String {
    use vortex_framework::ui::html_escape;
    let err_html = err
        .map(|e| format!(r#"<div class="alert alert-error text-sm mb-3">{}</div>"#, html_escape(e)))
        .unwrap_or_default();
    format!(
        r#"<!DOCTYPE html><html data-theme="dark"><head>
<title>Portal Sign in</title><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<script src="/static/vendor/tailwind.js"></script>
<style>body{{background:#0b0f0a;color:#e5e7eb}}</style></head>
<body class="min-h-screen flex items-center justify-center p-4">
<div class="w-full max-w-sm" style="background:#12160f;border:1px solid #263019;border-radius:.75rem;padding:1.5rem">
  <div class="text-center mb-5">
    <div class="text-2xl font-bold"><span style="color:#8BC53F">re</span><span style="color:#9ca3af">micle</span></div>
    <div class="text-sm mt-1" style="color:#9ca3af">Customer &amp; supplier portal</div>
  </div>
  {err_html}
  <form method="post" action="/portal/login" class="flex flex-col gap-3">
    <label class="text-sm">Username
      <input name="username" required autofocus autocomplete="username" class="input input-bordered w-full mt-1" style="background:#0b0f0a"/>
    </label>
    <label class="text-sm">Password
      <input name="password" type="password" required autocomplete="current-password" class="input input-bordered w-full mt-1" style="background:#0b0f0a"/>
    </label>
    <button class="btn mt-2" style="background:#8BC53F;border-color:#8BC53F;color:#000">Sign in</button>
  </form>
</div></body></html>"#,
        err_html = err_html,
    )
}

async fn portal_login_page() -> Response {
    Html(portal_login_html(None)).into_response()
}

/// POST /portal/login — authenticates ONLY `is_portal` users. An internal
/// account that tries here is refused (and vice-versa at `/auth/login`).
async fn portal_login_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<PortalLoginForm>,
) -> Response {
    let (client_ip, _ua) = request_fingerprint(&headers);
    let db_name = resolve_database(&state, &headers, form.database.as_deref()).await;
    let pool = match state.pool_manager.get_pool(&db_name).await {
        Ok(p) => p,
        Err(e) => {
            error!("portal login: pool for '{}' failed: {}", db_name, e);
            return Html(portal_login_html(Some("Service unavailable. Try again shortly."))).into_response();
        }
    };
    let db = pool.pool().clone();

    let row = sqlx::query(
        "SELECT id, password_hash, full_name, active, locked, is_portal, contact_id \
         FROM users WHERE username = $1",
    )
    .bind(&form.username)
    .fetch_optional(&db)
    .await;

    let audit_fail = |state: &Arc<AppState>, user_id: Option<uuid::Uuid>, reason: &'static str| {
        let mut e = AuditEntry::new(AuditAction::LoginFailure, AuditSeverity::Warning)
            .with_username(&form.username)
            .with_database(&db_name)
            .with_resource("portal_session", user_id.map(|u| u.to_string()).unwrap_or_else(|| "unknown".into()))
            .with_error(reason)
            .with_details(serde_json::json!({"reason": reason, "database": db_name, "surface": "portal"}));
        if let Some(u) = user_id {
            e = e.with_user(vortex_common::UserId(u));
        }
        if let Some(ip) = &client_ip {
            e = e.with_source_ip(ip.clone());
        }
        let audit = state.audit.clone();
        async move {
            if let Err(err) = audit.log(e).await {
                error!("WORM audit write failed for portal LoginFailure: {}", err);
            }
        }
    };

    let bad_creds = "Invalid username or password.";
    match row {
        Ok(Some(r)) => {
            let uid: uuid::Uuid = r.get("id");
            let is_portal: bool = r.get("is_portal");
            let active: bool = r.get("active");
            let locked: bool = r.get("locked");
            let hash: String = r.get("password_hash");
            let full_name: Option<String> = r.try_get("full_name").ok().flatten();
            let contact_id: Option<uuid::Uuid> = r.try_get("contact_id").ok().flatten();

            // Not a portal account → refuse here without confirming the password,
            // and don't leak that the username exists as a staff login.
            if !is_portal {
                audit_fail(&state, Some(uid), "not_portal_user").await;
                return Html(portal_login_html(Some(bad_creds))).into_response();
            }
            if !active || locked {
                audit_fail(&state, Some(uid), if locked { "locked" } else { "disabled" }).await;
                return Html(portal_login_html(Some("This account is not active. Contact your account manager."))).into_response();
            }
            if !verify_password(&form.password, &hash) {
                let _ = sqlx::query("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1")
                    .bind(uid).execute(&db).await;
                audit_fail(&state, Some(uid), "invalid_password").await;
                return Html(portal_login_html(Some(bad_creds))).into_response();
            }
            if contact_id.is_none() {
                // A portal user with no partner binding is a provisioning bug;
                // the CHECK constraint should prevent it, but fail safe.
                audit_fail(&state, Some(uid), "no_contact_binding").await;
                return Html(portal_login_html(Some("Your portal account is not fully set up. Contact your account manager."))).into_response();
            }

            let token = generate_session_token();
            let token_hash = hash_token(&token);
            if let Err(e) = sqlx::query(
                "INSERT INTO sessions (user_id, token_hash, expires_at, ip_address) \
                 VALUES ($1, $2, NOW() + INTERVAL '30 minutes', NULL)",
            )
            .bind(uid)
            .bind(&token_hash)
            .execute(&db)
            .await
            {
                error!("portal login: session insert failed: {}", e);
                return Html(portal_login_html(Some("Sign-in failed. Try again."))).into_response();
            }
            let _ = sqlx::query("UPDATE users SET last_login_at = NOW(), failed_login_attempts = 0 WHERE id = $1")
                .bind(uid).execute(&db).await;

            let mut entry = AuditEntry::new(AuditAction::LoginSuccess, AuditSeverity::Info)
                .with_user(vortex_common::UserId(uid))
                .with_username(&form.username)
                .with_database(&db_name)
                .with_resource("portal_session", uid.to_string())
                .with_details(serde_json::json!({"database": db_name, "surface": "portal"}));
            if let Some(ip) = &client_ip {
                entry = entry.with_source_ip(ip.clone());
            }
            if let Err(e) = state.audit.log(entry).await {
                error!("WORM audit write failed for portal LoginSuccess: {}", e);
            }
            let _ = full_name;

            let mut resp_headers = HeaderMap::new();
            resp_headers.insert(
                header::SET_COOKIE,
                format!("session={}|{}; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800", db_name, token)
                    .parse()
                    .unwrap(),
            );
            (resp_headers, Redirect::to("/portal")).into_response()
        }
        Ok(None) => {
            audit_fail(&state, None, "user_not_found").await;
            Html(portal_login_html(Some(bad_creds))).into_response()
        }
        Err(e) => {
            error!("portal login: db error: {}", e);
            Html(portal_login_html(Some("Sign-in failed. Try again."))).into_response()
        }
    }
}

async fn portal_logout(Db(db): Db, jar: HeaderMap) -> Response {
    // Best-effort session revocation, then clear the cookie.
    if let Some(cookie) = jar.get(header::COOKIE).and_then(|c| c.to_str().ok()) {
        if let Some(raw) = cookie.split(';').find_map(|kv| kv.trim().strip_prefix("session=")) {
            let token = raw.rsplit('|').next().unwrap_or(raw);
            let th = hash_token(token);
            let _ = sqlx::query("UPDATE sessions SET revoked = true, revoked_at = NOW(), revoked_reason = 'portal_logout' WHERE token_hash = $1")
                .bind(&th).execute(&db).await;
        }
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".parse().unwrap());
    (headers, Redirect::to("/portal/login")).into_response()
}

fn portal_redirect_login() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".parse().unwrap());
    (headers, Redirect::to("/portal/login")).into_response()
}

/// Guard for `/portal/*`: admits ONLY authenticated `is_portal` users, injects
/// their `AuthUser` (with `contact_id`) + tenant `DatabaseContext`. Anything
/// else is bounced to the portal login.
async fn portal_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let cookie = request
        .headers()
        .get(header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .and_then(|c| c.split(';').find_map(|kv| kv.trim().strip_prefix("session=").map(str::to_string)));
    let Some(raw) = cookie else { return portal_redirect_login() };

    // cookie is `db_name|token` (or a legacy bare token → default DB).
    let (db_name, token) = match raw.split_once('|') {
        Some((d, t)) => (d.to_string(), t.to_string()),
        None => (state.default_db.clone(), raw.clone()),
    };
    if !db_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return portal_redirect_login();
    }
    let pool = match state.pool_manager.get_pool(&db_name).await {
        Ok(p) => p,
        Err(_) => return portal_redirect_login(),
    };
    let db = pool.pool().clone();

    let token_hash = hash_token(&token);
    let row = sqlx::query(
        "SELECT s.id as session_id, s.user_id, s.expires_at, s.last_activity_at, s.revoked, \
                u.username, u.full_name, u.active, u.locked, u.is_portal, u.contact_id \
         FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token_hash = $1",
    )
    .bind(&token_hash)
    .fetch_optional(&db)
    .await;

    let Ok(Some(r)) = row else { return portal_redirect_login() };
    let revoked: bool = r.get("revoked");
    let expires_at: chrono::DateTime<chrono::Utc> = r.get("expires_at");
    let active: bool = r.get("active");
    let locked: bool = r.get("locked");
    let is_portal: bool = r.get("is_portal");
    let contact_id: Option<uuid::Uuid> = r.try_get("contact_id").ok().flatten();
    if revoked || expires_at < chrono::Utc::now() || !active || locked || !is_portal || contact_id.is_none() {
        return portal_redirect_login();
    }

    let session_id: uuid::Uuid = r.get("session_id");
    let user_id: uuid::Uuid = r.get("user_id");
    let last_activity: Option<chrono::DateTime<chrono::Utc>> = r.try_get("last_activity_at").ok().flatten();
    let refresh_due = last_activity.map_or(true, |t| chrono::Utc::now() - t > chrono::Duration::seconds(60));
    if refresh_due {
        let _ = sqlx::query("UPDATE sessions SET last_activity_at = NOW(), expires_at = NOW() + INTERVAL '30 minutes' WHERE id = $1")
            .bind(session_id).execute(&db).await;
    }

    let db_installed_modules: HashSet<String> = sqlx::query_scalar(
        "SELECT technical_name FROM installed_modules WHERE state = 'installed'",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    let auth_user = AuthUser {
        id: user_id,
        username: r.get("username"),
        full_name: r.try_get("full_name").ok().flatten(),
        session_id,
        roles: vec!["Portal User".to_string()],
        contact_id,
        is_portal: true,
    };
    request.extensions_mut().insert(auth_user);
    request.extensions_mut().insert(pool.clone());
    request.extensions_mut().insert(DatabaseContext {
        db_name,
        pool,
        installed_modules: db_installed_modules,
    });
    next.run(request).await
}

/// The signed-in portal user's partner id, or a redirect if somehow absent
/// (the middleware guarantees it, so this is defence-in-depth).
fn portal_partner(user: &AuthUser) -> Result<uuid::Uuid, Response> {
    user.portal_contact_id().ok_or_else(portal_redirect_login)
}

async fn portal_home(Db(db): Db, Extension(user): Extension<AuthUser>) -> Response {
    use vortex_framework::ui::html_escape;
    let partner = match portal_partner(&user) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let name: String = sqlx::query_scalar("SELECT name FROM contacts WHERE id = $1")
        .bind(partner).fetch_optional(&db).await.ok().flatten().unwrap_or_else(|| user.username.clone());

    // Outstanding balance + open-invoice count (posted customer invoices/credit notes).
    let outstanding: f64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_residual),0)::float8 FROM acc_move \
         WHERE partner_id = $1 AND state = 'posted' \
           AND move_type IN ('customer_invoice','customer_credit_note') \
           AND payment_state IN ('not_paid','partial')",
    ).bind(partner).fetch_one(&db).await.unwrap_or(0.0);
    let open_invoices: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM acc_move WHERE partner_id = $1 AND state='posted' \
           AND move_type IN ('customer_invoice','customer_credit_note') \
           AND payment_state IN ('not_paid','partial')",
    ).bind(partner).fetch_one(&db).await.unwrap_or(0);
    let open_orders: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_order WHERE customer_id = $1 AND state IN ('confirmed','draft')",
    ).bind(partner).fetch_one(&db).await.unwrap_or(0);

    let body = format!(
        r#"<h1 class="text-2xl font-bold mb-1">Welcome, {name}</h1>
<p class="text-base-content/60 mb-5">Your account at a glance.</p>
<div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
  <a href="/portal/statement" class="pcard p-4 block hover:border-primary">
    <div class="text-sm text-base-content/60">Outstanding balance</div>
    <div class="text-2xl font-bold mt-1" style="color:#8BC53F">{outstanding}</div>
  </a>
  <a href="/portal/invoices" class="pcard p-4 block hover:border-primary">
    <div class="text-sm text-base-content/60">Open invoices</div>
    <div class="text-2xl font-bold mt-1">{open_invoices}</div>
  </a>
  <a href="/portal/orders" class="pcard p-4 block hover:border-primary">
    <div class="text-sm text-base-content/60">Active orders</div>
    <div class="text-2xl font-bold mt-1">{open_orders}</div>
  </a>
</div>
<div class="pcard p-4">
  <div class="font-semibold mb-2">Quick links</div>
  <ul class="list-disc pl-5 text-sm space-y-1">
    <li><a href="/portal/invoices" class="link">View and track your invoices</a></li>
    <li><a href="/portal/statement" class="link">See your statement of account</a></li>
    <li><a href="/portal/orders" class="link">Review your orders</a></li>
  </ul>
</div>"#,
        name = html_escape(&name),
        outstanding = portal_money(outstanding),
        open_invoices = open_invoices,
        open_orders = open_orders,
    );
    Html(portal_shell("Home", &name, "home", &body)).into_response()
}

async fn portal_partner_name(db: &PgPool, partner: uuid::Uuid, fallback: &str) -> String {
    sqlx::query_scalar("SELECT name FROM contacts WHERE id = $1")
        .bind(partner).fetch_optional(db).await.ok().flatten().unwrap_or_else(|| fallback.to_string())
}

async fn portal_invoices(Db(db): Db, Extension(user): Extension<AuthUser>) -> Response {
    use vortex_framework::ui::html_escape;
    let partner = match portal_partner(&user) { Ok(p) => p, Err(r) => return r };
    let name = portal_partner_name(&db, partner, &user.username).await;

    let rows = sqlx::query(
        "SELECT id, number, move_type, invoice_date, due_date, \
                total_amount::float8 AS total, amount_residual::float8 AS residual, payment_state \
         FROM acc_move \
         WHERE partner_id = $1 AND state = 'posted' \
           AND move_type IN ('customer_invoice','customer_credit_note') \
         ORDER BY COALESCE(invoice_date, move_date) DESC, number DESC LIMIT 500",
    )
    .bind(partner)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut trs = String::new();
    for r in &rows {
        let id: uuid::Uuid = r.get("id");
        let number: Option<String> = r.try_get("number").ok().flatten();
        let mtype: String = r.get("move_type");
        let inv_date: Option<chrono::NaiveDate> = r.try_get("invoice_date").ok().flatten();
        let due: Option<chrono::NaiveDate> = r.try_get("due_date").ok().flatten();
        let total: f64 = r.try_get("total").unwrap_or(0.0);
        let residual: f64 = r.try_get("residual").unwrap_or(0.0);
        let pstate: String = r.get("payment_state");
        let is_cn = mtype == "customer_credit_note";
        let badge = match pstate.as_str() {
            "paid" => r#"<span class="badge badge-success badge-sm">Paid</span>"#,
            "partial" => r#"<span class="badge badge-warning badge-sm">Partial</span>"#,
            "reversed" => r#"<span class="badge badge-ghost badge-sm">Reversed</span>"#,
            _ => r#"<span class="badge badge-error badge-sm">Unpaid</span>"#,
        };
        trs.push_str(&format!(
            r#"<tr>
<td><a class="link" href="/portal/invoices/{id}">{num}</a>{cn}</td>
<td>{date}</td><td>{due}</td>
<td class="num">{total}</td><td class="num">{residual}</td><td>{badge}</td></tr>"#,
            id = id,
            num = html_escape(number.as_deref().unwrap_or("—")),
            cn = if is_cn { r#" <span class="badge badge-outline badge-sm">Credit</span>"# } else { "" },
            date = inv_date.map(|d| d.to_string()).unwrap_or_default(),
            due = due.map(|d| d.to_string()).unwrap_or_default(),
            total = portal_money(total),
            residual = portal_money(residual),
            badge = badge,
        ));
    }
    if rows.is_empty() {
        trs = r#"<tr><td colspan="6" class="text-base-content/50 text-center py-6">No invoices yet.</td></tr>"#.to_string();
    }

    let body = format!(
        r#"<h1 class="text-2xl font-bold mb-4">Invoices</h1>
<div class="pcard overflow-x-auto">
<table class="ptbl"><thead><tr>
<th>Number</th><th>Date</th><th>Due</th><th class="num">Total</th><th class="num">Balance</th><th>Status</th>
</tr></thead><tbody>{trs}</tbody></table></div>"#,
        trs = trs,
    );
    Html(portal_shell("Invoices", &name, "invoices", &body)).into_response()
}

async fn portal_invoice_detail(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    use vortex_framework::ui::html_escape;
    let partner = match portal_partner(&user) { Ok(p) => p, Err(r) => return r };
    let name = portal_partner_name(&db, partner, &user.username).await;

    // Ownership re-check: the invoice must belong to THIS partner.
    let head = sqlx::query(
        "SELECT number, move_type, invoice_date, due_date, \
                total_amount::float8 AS total, amount_residual::float8 AS residual, payment_state \
         FROM acc_move WHERE id = $1 AND partner_id = $2 AND state = 'posted' \
           AND move_type IN ('customer_invoice','customer_credit_note')",
    )
    .bind(id)
    .bind(partner)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(h) = head else {
        let body = r#"<div class="pcard p-6 text-center text-base-content/60">Invoice not found. <a class="link" href="/portal/invoices">Back to invoices</a>.</div>"#;
        return (StatusCode::NOT_FOUND, Html(portal_shell("Not found", &name, "invoices", body))).into_response();
    };
    let number: Option<String> = h.try_get("number").ok().flatten();
    let inv_date: Option<chrono::NaiveDate> = h.try_get("invoice_date").ok().flatten();
    let due: Option<chrono::NaiveDate> = h.try_get("due_date").ok().flatten();
    let total: f64 = h.try_get("total").unwrap_or(0.0);
    let residual: f64 = h.try_get("residual").unwrap_or(0.0);
    let pstate: String = h.get("payment_state");

    // Lines the customer actually cares about: the revenue/tax charges, not the
    // receivable or payable control lines (which just mirror the total). `credit
    // - debit` renders each charge as a positive amount on a customer invoice.
    let lines = sqlx::query(
        "SELECT l.name, (l.credit - l.debit)::float8 AS amount \
         FROM acc_move_line l JOIN acc_account a ON a.id = l.account_id \
         WHERE l.move_id = $1 \
           AND a.account_type NOT IN ('asset_receivable','liability_payable') \
           AND (l.debit <> 0 OR l.credit <> 0) \
         ORDER BY l.sequence, l.id",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut line_html = String::new();
    for l in &lines {
        let lbl: Option<String> = l.try_get("name").ok().flatten();
        let amt: f64 = l.try_get("amount").unwrap_or(0.0);
        line_html.push_str(&format!(
            r#"<tr><td>{}</td><td class="num">{}</td></tr>"#,
            html_escape(lbl.as_deref().unwrap_or("—")),
            portal_money(amt),
        ));
    }
    if lines.is_empty() {
        line_html = r#"<tr><td colspan="2" class="text-base-content/50 py-4 text-center">No line detail.</td></tr>"#.to_string();
    }

    let body = format!(
        r#"<div class="mb-4"><a class="link text-sm" href="/portal/invoices">&larr; Invoices</a></div>
<h1 class="text-2xl font-bold mb-1">Invoice {num}</h1>
<div class="text-base-content/60 mb-4">Issued {date} · Due {due} · Status: {pstate}</div>
<div class="pcard overflow-x-auto mb-4">
<table class="ptbl"><thead><tr><th>Description</th><th class="num">Amount</th></tr></thead>
<tbody>{lines}</tbody>
<tfoot>
<tr><th>Total</th><th class="num">{total}</th></tr>
<tr><th>Balance due</th><th class="num">{residual}</th></tr>
</tfoot></table></div>"#,
        num = html_escape(number.as_deref().unwrap_or("—")),
        date = inv_date.map(|d| d.to_string()).unwrap_or_else(|| "—".into()),
        due = due.map(|d| d.to_string()).unwrap_or_else(|| "—".into()),
        pstate = html_escape(&pstate),
        lines = line_html,
        total = portal_money(total),
        residual = portal_money(residual),
    );
    Html(portal_shell(&format!("Invoice {}", number.as_deref().unwrap_or("")), &name, "invoices", &body)).into_response()
}

async fn portal_orders(Db(db): Db, Extension(user): Extension<AuthUser>) -> Response {
    use vortex_framework::ui::html_escape;
    let partner = match portal_partner(&user) { Ok(p) => p, Err(r) => return r };
    let name = portal_partner_name(&db, partner, &user.username).await;

    let rows = sqlx::query(
        "SELECT number, order_date, state, total_amount::float8 AS total \
         FROM sales_order WHERE customer_id = $1 \
         ORDER BY order_date DESC, number DESC LIMIT 500",
    )
    .bind(partner)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut trs = String::new();
    for r in &rows {
        let number: Option<String> = r.try_get("number").ok().flatten();
        let odate: Option<chrono::NaiveDate> = r.try_get("order_date").ok().flatten();
        let state: String = r.try_get("state").ok().flatten().unwrap_or_default();
        let total: f64 = r.try_get("total").unwrap_or(0.0);
        let badge = match state.as_str() {
            "delivered" => r#"<span class="badge badge-success badge-sm">Delivered</span>"#,
            "confirmed" => r#"<span class="badge badge-info badge-sm">Confirmed</span>"#,
            "cancelled" => r#"<span class="badge badge-ghost badge-sm">Cancelled</span>"#,
            _ => r#"<span class="badge badge-warning badge-sm">Draft</span>"#,
        };
        trs.push_str(&format!(
            r#"<tr><td>{num}</td><td>{date}</td><td>{badge}</td><td class="num">{total}</td></tr>"#,
            num = html_escape(number.as_deref().unwrap_or("—")),
            date = odate.map(|d| d.to_string()).unwrap_or_default(),
            badge = badge,
            total = portal_money(total),
        ));
    }
    if rows.is_empty() {
        trs = r#"<tr><td colspan="4" class="text-base-content/50 text-center py-6">No orders yet.</td></tr>"#.to_string();
    }

    let body = format!(
        r#"<h1 class="text-2xl font-bold mb-4">Orders</h1>
<div class="pcard overflow-x-auto">
<table class="ptbl"><thead><tr><th>Number</th><th>Date</th><th>Status</th><th class="num">Total</th></tr></thead>
<tbody>{trs}</tbody></table></div>"#,
        trs = trs,
    );
    Html(portal_shell("Orders", &name, "orders", &body)).into_response()
}

async fn portal_statement(Db(db): Db, Extension(user): Extension<AuthUser>) -> Response {
    use vortex_framework::ui::html_escape;
    let partner = match portal_partner(&user) { Ok(p) => p, Err(r) => return r };
    let name = portal_partner_name(&db, partner, &user.username).await;

    // Open items with ageing, scoped to this partner's receivables.
    let rows = sqlx::query(
        "SELECT number, invoice_date, due_date, amount_residual::float8 AS residual, \
                GREATEST(0, (CURRENT_DATE - due_date))::int AS days_overdue \
         FROM acc_move \
         WHERE partner_id = $1 AND state = 'posted' \
           AND move_type IN ('customer_invoice','customer_credit_note') \
           AND payment_state IN ('not_paid','partial') AND amount_residual <> 0 \
         ORDER BY due_date NULLS LAST, invoice_date",
    )
    .bind(partner)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut buckets = [0f64; 4]; // current, 1-30, 31-60, 60+
    let mut total = 0f64;
    let mut trs = String::new();
    for r in &rows {
        let number: Option<String> = r.try_get("number").ok().flatten();
        let inv_date: Option<chrono::NaiveDate> = r.try_get("invoice_date").ok().flatten();
        let due: Option<chrono::NaiveDate> = r.try_get("due_date").ok().flatten();
        let residual: f64 = r.try_get("residual").unwrap_or(0.0);
        let overdue: i32 = r.try_get("days_overdue").unwrap_or(0);
        total += residual;
        let bucket = if overdue <= 0 { 0 } else if overdue <= 30 { 1 } else if overdue <= 60 { 2 } else { 3 };
        buckets[bucket] += residual;
        trs.push_str(&format!(
            r#"<tr><td>{num}</td><td>{date}</td><td>{due}</td><td class="num">{days}</td><td class="num">{amt}</td></tr>"#,
            num = html_escape(number.as_deref().unwrap_or("—")),
            date = inv_date.map(|d| d.to_string()).unwrap_or_default(),
            due = due.map(|d| d.to_string()).unwrap_or_default(),
            days = if overdue > 0 { overdue.to_string() } else { "—".to_string() },
            amt = portal_money(residual),
        ));
    }
    if rows.is_empty() {
        trs = r#"<tr><td colspan="5" class="text-base-content/50 text-center py-6">Nothing outstanding — your account is settled.</td></tr>"#.to_string();
    }

    let body = format!(
        r#"<h1 class="text-2xl font-bold mb-1">Statement of account</h1>
<p class="text-base-content/60 mb-4">Open items for <strong>{name}</strong>.</p>
<div class="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-5">
  <div class="pcard p-3"><div class="text-xs text-base-content/60">Total due</div><div class="font-bold" style="color:#8BC53F">{total}</div></div>
  <div class="pcard p-3"><div class="text-xs text-base-content/60">Current</div><div class="font-bold">{b0}</div></div>
  <div class="pcard p-3"><div class="text-xs text-base-content/60">1–30 days</div><div class="font-bold">{b1}</div></div>
  <div class="pcard p-3"><div class="text-xs text-base-content/60">31–60 days</div><div class="font-bold">{b2}</div></div>
  <div class="pcard p-3"><div class="text-xs text-base-content/60">60+ days</div><div class="font-bold text-error">{b3}</div></div>
</div>
<div class="pcard overflow-x-auto">
<table class="ptbl"><thead><tr><th>Invoice</th><th>Date</th><th>Due</th><th class="num">Days overdue</th><th class="num">Balance</th></tr></thead>
<tbody>{trs}</tbody>
<tfoot><tr><th colspan="4">Total outstanding</th><th class="num">{total}</th></tr></tfoot></table></div>"#,
        name = html_escape(&name),
        total = portal_money(total),
        b0 = portal_money(buckets[0]),
        b1 = portal_money(buckets[1]),
        b2 = portal_money(buckets[2]),
        b3 = portal_money(buckets[3]),
        trs = trs,
    );
    Html(portal_shell("Statement", &name, "statement", &body)).into_response()
}

// ── Portal provisioning (Phase 3) — staff-facing invite/revoke + accept ──────
//
// Staff invite a partner from `/settings/portal-users`: the portal `users` row
// is created inactive with a placeholder password, a single-use invite token is
// issued (only its hash stored), and the invitee sets a password via the emailed
// `/portal/invite/{token}` link, which activates the account.

/// An unusable password placeholder — never a valid PHC string, so
/// `verify_password` can never match it even if `active` were somehow true.
const PORTAL_INVITE_PLACEHOLDER: &str = "!invite-pending";

fn absolute_url(headers: &HeaderMap, path: &str) -> String {
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("localhost:3000");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if host.starts_with("localhost") || host.starts_with("127.") { "http".into() } else { "https".into() }
        });
    format!("{proto}://{host}{path}")
}

fn portal_admin_shell(user: &AuthUser, title: &str, inner: &str) -> Html<String> {
    use vortex_framework::ui::html_escape;
    Html(format!(
        r##"<!DOCTYPE html><html lang="en" data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>{title} - Settings</title>
<link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="navbar bg-base-100 shadow-lg"><div class="flex-1"><a href="/settings" class="btn btn-ghost text-xl">remicle</a></div><div class="flex-none"><span class="text-sm">@{user}</span></div></div>
<div class="container mx-auto p-6 max-w-5xl">{inner}</div></body></html>"##,
        title = html_escape(title),
        user = html_escape(&user.username),
        inner = inner,
    ))
}

async fn portal_users_list(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    use vortex_framework::ui::html_escape;
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Portal Users"))).into_response();
    }

    // Existing portal users + their partner + invite status.
    let users = sqlx::query(
        "SELECT u.id, u.username, u.email, u.active, u.last_login_at, c.name AS contact_name, \
                EXISTS(SELECT 1 FROM portal_invite i WHERE i.user_id = u.id AND i.consumed_at IS NULL AND i.expires_at > NOW()) AS pending \
         FROM users u LEFT JOIN contacts c ON c.id = u.contact_id \
         WHERE u.is_portal = true ORDER BY u.username",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows = String::new();
    for u in &users {
        let id: uuid::Uuid = u.get("id");
        let uname: String = u.get("username");
        let email: Option<String> = u.try_get("email").ok().flatten();
        let active: bool = u.get("active");
        let pending: bool = u.try_get("pending").unwrap_or(false);
        let contact: Option<String> = u.try_get("contact_name").ok().flatten();
        let last: Option<chrono::DateTime<chrono::Utc>> = u.try_get("last_login_at").ok().flatten();
        let status = if active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else if pending {
            r#"<span class="badge badge-info badge-sm">Invited</span>"#
        } else {
            r#"<span class="badge badge-ghost badge-sm">Disabled</span>"#
        };
        let actions = if active {
            format!(r#"<form method="post" action="/settings/portal-users/{id}/revoke" class="inline" onsubmit="return confirm('Disable this portal login? They will be signed out immediately.')"><button class="btn btn-xs btn-error btn-outline">Disable</button></form>"#, id = id)
        } else {
            format!(r#"<form method="post" action="/settings/portal-users/{id}/resend" class="inline"><button class="btn btn-xs btn-outline">Resend invite</button></form>"#, id = id)
        };
        rows.push_str(&format!(
            r##"<tr><td>{contact}</td><td class="text-xs">@{uname}</td><td class="text-xs">{email}</td><td class="text-xs">{last}</td><td>{status}</td><td class="text-right">{actions}</td></tr>"##,
            contact = html_escape(contact.as_deref().unwrap_or("—")),
            uname = html_escape(&uname),
            email = html_escape(email.as_deref().unwrap_or("—")),
            last = last.map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "—".into()),
            status = status,
            actions = actions,
        ));
    }
    if users.is_empty() {
        rows.push_str(r#"<tr><td colspan="6" class="text-center opacity-50 py-8">No portal users yet — invite a customer below.</td></tr>"#);
    }

    // Eligible contacts: customers without a portal login yet.
    let contacts = sqlx::query(
        "SELECT c.id, c.name FROM contacts c \
         WHERE c.contact_type IN ('customer','both') AND c.active = true \
           AND NOT EXISTS (SELECT 1 FROM users u WHERE u.contact_id = c.id AND u.is_portal = true) \
         ORDER BY c.name LIMIT 1000",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut options = String::new();
    for c in &contacts {
        let id: uuid::Uuid = c.get("id");
        let name: String = c.get("name");
        options.push_str(&format!(r#"<option value="{id}">{name}</option>"#, id = id, name = html_escape(&name)));
    }
    let invite_card = if contacts.is_empty() {
        r#"<div class="alert">Every active customer already has a portal login.</div>"#.to_string()
    } else {
        format!(
            r##"<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<h2 class="card-title text-lg">Invite a customer</h2>
<p class="text-base-content/60 text-sm">Creates a self-service login bound to the selected customer and emails them a link to set a password. They only ever see their own documents.</p>
<form method="post" action="/settings/portal-users/invite" class="grid md:grid-cols-3 gap-3 items-end">
<label class="form-control"><span class="label-text">Customer</span><select name="contact_id" required class="select select-bordered select-sm">{options}</select></label>
<label class="form-control"><span class="label-text">Email</span><input name="email" type="email" required placeholder="person@company.com" class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text">Username (optional)</span><input name="username" placeholder="defaults to email" class="input input-bordered input-sm"/></label>
<div class="md:col-span-3"><button class="btn btn-primary btn-sm">Send invitation</button></div>
</form></div></div>"##,
            options = options,
        )
    };

    let inner = format!(
        r##"<div class="mb-4"><h1 class="text-2xl font-bold">Portal Users</h1>
<p class="text-base-content/60">External customer self-service logins. Each is bound to one contact and confined to <code>/portal</code>.</p></div>
{invite_card}
<div class="card bg-base-100 shadow"><div class="card-body">
<table class="table table-sm"><thead><tr><th>Customer</th><th>Username</th><th>Email</th><th>Last login</th><th>Status</th><th></th></tr></thead>
<tbody>{rows}</tbody></table></div></div>"##,
        invite_card = invite_card,
        rows = rows,
    );
    portal_admin_shell(&user, "Portal Users", &inner).into_response()
}

#[derive(serde::Deserialize)]
struct PortalInviteForm {
    contact_id: uuid::Uuid,
    email: String,
    username: Option<String>,
}

/// Create the invite token row + email it. Shared by invite and resend. Returns
/// the absolute accept link so the caller can also show it to the admin.
async fn issue_portal_invite(
    db: &PgPool,
    headers: &HeaderMap,
    user_id: uuid::Uuid,
    email: &str,
    inviter: uuid::Uuid,
) -> Result<String, String> {
    // Invalidate any outstanding invites for this user first.
    let _ = sqlx::query("UPDATE portal_invite SET consumed_at = NOW() WHERE user_id = $1 AND consumed_at IS NULL")
        .bind(user_id).execute(db).await;
    let token = generate_session_token();
    let token_hash = hash_token(&token);
    sqlx::query(
        "INSERT INTO portal_invite (user_id, token_hash, email, expires_at, created_by) \
         VALUES ($1, $2, $3, NOW() + INTERVAL '7 days', $4)",
    )
    .bind(user_id)
    .bind(&token_hash)
    .bind(email)
    .bind(inviter)
    .execute(db)
    .await
    .map_err(|e| format!("could not create invite: {e}"))?;

    let link = absolute_url(headers, &format!("/portal/invite/{token}"));
    let msg = vortex_framework::mail::EmailMessage::text(
        email,
        "You're invited to the customer portal",
        format!(
            "Hello,\n\nYou've been given access to the customer self-service portal, where you can view your invoices, orders and account statement.\n\nSet your password to get started:\n{link}\n\nThis link expires in 7 days.\n"
        ),
    )
    .with_html(format!(
        r#"<p>Hello,</p><p>You've been given access to the customer self-service portal, where you can view your invoices, orders and account statement.</p><p><a href="{link}" style="display:inline-block;padding:.6rem 1rem;background:#8BC53F;color:#000;border-radius:.4rem;text-decoration:none">Set your password</a></p><p style="color:#666;font-size:.85rem">Or paste this link into your browser: {link}<br>This link expires in 7 days.</p>"#
    ));
    // Best-effort: a missing SMTP config must not block provisioning — the admin
    // can copy the link shown on the result page.
    let _ = vortex_framework::mail::send_default(db, &msg, "portal_invite").await;
    Ok(link)
}

async fn portal_user_invite(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    headers: HeaderMap,
    Form(form): Form<PortalInviteForm>,
) -> Response {
    use vortex_framework::ui::html_escape;
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Portal Users"))).into_response();
    }
    let email = form.email.trim().to_string();
    let username = form.username.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(&email).to_string();
    let back = r#"<a href="/settings/portal-users" class="btn btn-sm mt-4">Back</a>"#;
    let err = |e: String| portal_admin_shell(&user, "Portal Users", &format!(r#"<div class="alert alert-error">{}</div>{}"#, html_escape(&e), back)).into_response();

    if email.is_empty() || !email.contains('@') {
        return err("A valid email is required.".into());
    }
    // Contact must exist and be a customer.
    let contact = sqlx::query("SELECT name, company_id, contact_type FROM contacts WHERE id = $1 AND active = true")
        .bind(form.contact_id).fetch_optional(&db).await.ok().flatten();
    let Some(contact) = contact else { return err("That customer no longer exists.".into()) };
    let ctype: String = contact.get("contact_type");
    if !matches!(ctype.as_str(), "customer" | "both") {
        return err("Portal logins can only be created for customers.".into());
    }
    let contact_name: String = contact.get("name");
    let company_id: Option<uuid::Uuid> = contact.try_get("company_id").ok().flatten();

    // One portal login per contact.
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE contact_id = $1 AND is_portal = true")
        .bind(form.contact_id).fetch_one(&db).await.unwrap_or(0);
    if exists > 0 {
        return err(format!("{contact_name} already has a portal login."));
    }
    // Username must be free.
    let taken: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1")
        .bind(&username).fetch_one(&db).await.unwrap_or(0);
    if taken > 0 {
        return err(format!("The username {username:?} is taken — pick another."));
    }

    let placeholder = hash_password(PORTAL_INVITE_PLACEHOLDER);
    let new_id: Result<uuid::Uuid, _> = sqlx::query_scalar(
        "INSERT INTO users (company_id, username, email, password_hash, full_name, active, is_portal, contact_id, password_changed_at) \
         VALUES ($1, $2, $3, $4, $5, false, true, $6, NOW()) RETURNING id",
    )
    .bind(company_id)
    .bind(&username)
    .bind(&email)
    .bind(&placeholder)
    .bind(&contact_name)
    .bind(form.contact_id)
    .fetch_one(&db)
    .await;
    let new_id = match new_id {
        Ok(id) => id,
        Err(e) => return err(format!("Could not create the login: {e}")),
    };
    let _ = sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, '00000000-0000-0000-0000-000000000005') ON CONFLICT DO NOTHING")
        .bind(new_id).execute(&db).await;

    let link = match issue_portal_invite(&db, &headers, new_id, &email, user.id).await {
        Ok(l) => l,
        Err(e) => return err(e),
    };

    // Audit the provisioning (state-changing).
    api_audit(
        &state, &db_ctx.db_name, &user,
        AuditAction::Custom("portal_user_invited".into()), AuditSeverity::Warning,
        "portal_user", Some(&new_id.to_string()),
        serde_json::json!({"contact_id": form.contact_id, "email": email, "username": username}),
    ).await;

    let inner = format!(
        r##"<div class="mb-4"><h1 class="text-2xl font-bold">Invitation sent</h1></div>
<div class="alert alert-success mb-4"><span>Portal login created for <strong>{contact}</strong> and an invite emailed to <strong>{email}</strong>.</span></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<p class="text-sm text-base-content/60">If email isn't configured, share this one-time link (expires in 7 days):</p>
<code class="text-xs break-all bg-base-200 p-2 rounded">{link}</code>
<a href="/settings/portal-users" class="btn btn-primary btn-sm mt-4 w-fit">Done</a>
</div></div>"##,
        contact = html_escape(&contact_name),
        email = html_escape(&email),
        link = html_escape(&link),
    );
    portal_admin_shell(&user, "Portal Users", &inner).into_response()
}

async fn portal_user_revoke(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Portal Users"))).into_response();
    }
    // Only ever touch portal accounts.
    let affected = sqlx::query("UPDATE users SET active = false WHERE id = $1 AND is_portal = true")
        .bind(id).execute(&db).await.map(|r| r.rows_affected()).unwrap_or(0);
    if affected > 0 {
        let _ = sqlx::query("UPDATE sessions SET revoked = true, revoked_at = NOW(), revoked_reason = 'portal_access_revoked' WHERE user_id = $1 AND revoked = false")
            .bind(id).execute(&db).await;
        let _ = sqlx::query("UPDATE portal_invite SET consumed_at = NOW() WHERE user_id = $1 AND consumed_at IS NULL")
            .bind(id).execute(&db).await;
        api_audit(
            &state, &db_ctx.db_name, &user,
            AuditAction::Custom("portal_user_revoked".into()), AuditSeverity::Warning,
            "portal_user", Some(&id.to_string()), serde_json::json!({}),
        ).await;
    }
    Redirect::to("/settings/portal-users").into_response()
}

async fn portal_user_resend(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    use vortex_framework::ui::html_escape;
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Portal Users"))).into_response();
    }
    let row = sqlx::query("SELECT email FROM users WHERE id = $1 AND is_portal = true AND active = false")
        .bind(id).fetch_optional(&db).await.ok().flatten();
    let Some(row) = row else { return Redirect::to("/settings/portal-users").into_response() };
    let email: Option<String> = row.try_get("email").ok().flatten();
    let Some(email) = email else { return Redirect::to("/settings/portal-users").into_response() };
    let link = match issue_portal_invite(&db, &headers, id, &email, user.id).await {
        Ok(l) => l,
        Err(e) => return portal_admin_shell(&user, "Portal Users", &format!(r#"<div class="alert alert-error">{}</div><a href="/settings/portal-users" class="btn btn-sm mt-4">Back</a>"#, html_escape(&e))).into_response(),
    };
    let inner = format!(
        r##"<div class="mb-4"><h1 class="text-2xl font-bold">Invitation re-sent</h1></div>
<div class="alert alert-success mb-4"><span>A fresh invite was emailed to <strong>{email}</strong>.</span></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<p class="text-sm text-base-content/60">One-time link (expires in 7 days):</p>
<code class="text-xs break-all bg-base-200 p-2 rounded">{link}</code>
<a href="/settings/portal-users" class="btn btn-primary btn-sm mt-4 w-fit">Done</a></div></div>"##,
        email = html_escape(&email),
        link = html_escape(&link),
    );
    portal_admin_shell(&user, "Portal Users", &inner).into_response()
}

/// GET /settings/portal-users/contact/{id} — the portal panel for one contact,
/// reachable from the "Invite to portal" button on the contact record. Shows an
/// invite form for a customer with no login yet, or the current login's status
/// with manage actions.
async fn portal_user_for_contact(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    use vortex_framework::ui::html_escape;
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Portal Users"))).into_response();
    }
    let back = r#"<a href="/settings/portal-users" class="btn btn-sm btn-ghost mt-4">All portal users</a>"#;
    let contact = sqlx::query("SELECT name, contact_type FROM contacts WHERE id = $1")
        .bind(id).fetch_optional(&db).await.ok().flatten();
    let Some(contact) = contact else {
        return portal_admin_shell(&user, "Portal Users", &format!(r#"<div class="alert alert-error">Contact not found.</div>{back}"#)).into_response();
    };
    let cname: String = contact.get("name");
    let ctype: String = contact.get("contact_type");
    if !matches!(ctype.as_str(), "customer" | "both") {
        return portal_admin_shell(&user, "Portal Users", &format!(
            r#"<div class="mb-4"><h1 class="text-2xl font-bold">Portal access</h1></div><div class="alert">Portal logins are only available for customers. <strong>{}</strong> is not a customer.</div>{back}"#,
            html_escape(&cname),
        )).into_response();
    }

    let existing = sqlx::query(
        "SELECT u.id, u.username, u.email, u.active, u.last_login_at, \
                EXISTS(SELECT 1 FROM portal_invite i WHERE i.user_id = u.id AND i.consumed_at IS NULL AND i.expires_at > NOW()) AS pending \
         FROM users u WHERE u.contact_id = $1 AND u.is_portal = true",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let inner = if let Some(u) = existing {
        let uid: uuid::Uuid = u.get("id");
        let uname: String = u.get("username");
        let email: Option<String> = u.try_get("email").ok().flatten();
        let active: bool = u.get("active");
        let pending: bool = u.try_get("pending").unwrap_or(false);
        let last: Option<chrono::DateTime<chrono::Utc>> = u.try_get("last_login_at").ok().flatten();
        let (status, action) = if active {
            (
                r#"<span class="badge badge-success">Active</span>"#.to_string(),
                format!(r#"<form method="post" action="/settings/portal-users/{uid}/revoke" onsubmit="return confirm('Disable this portal login? They will be signed out immediately.')"><button class="btn btn-sm btn-error btn-outline">Disable access</button></form>"#),
            )
        } else if pending {
            (
                r#"<span class="badge badge-info">Invited (awaiting sign-up)</span>"#.to_string(),
                format!(r#"<form method="post" action="/settings/portal-users/{uid}/resend"><button class="btn btn-sm btn-outline">Resend invite</button></form>"#),
            )
        } else {
            (
                r#"<span class="badge badge-ghost">Disabled</span>"#.to_string(),
                format!(r#"<form method="post" action="/settings/portal-users/{uid}/resend"><button class="btn btn-sm btn-outline">Re-invite</button></form>"#),
            )
        };
        format!(
            r##"<div class="mb-4"><h1 class="text-2xl font-bold">Portal access · {cname}</h1></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex items-center justify-between flex-wrap gap-3">
  <div>
    <div>Username: <code>@{uname}</code></div>
    <div class="text-sm text-base-content/60">Email: {email} · Last login: {last}</div>
    <div class="mt-2">{status}</div>
  </div>
  <div>{action}</div>
</div></div></div>{back}"##,
            cname = html_escape(&cname),
            uname = html_escape(&uname),
            email = html_escape(email.as_deref().unwrap_or("—")),
            last = last.map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "never".into()),
            status = status,
            action = action,
            back = back,
        )
    } else {
        // No login yet → pre-filled invite form locked to this contact.
        format!(
            r##"<div class="mb-4"><h1 class="text-2xl font-bold">Invite {cname} to the portal</h1>
<p class="text-base-content/60">Creates a self-service login bound to this customer and emails them a link to set a password. They only ever see their own documents.</p></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<form method="post" action="/settings/portal-users/invite" class="grid md:grid-cols-2 gap-3 items-end">
<input type="hidden" name="contact_id" value="{id}"/>
<label class="form-control"><span class="label-text">Email</span><input name="email" type="email" required placeholder="person@company.com" class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text">Username (optional)</span><input name="username" placeholder="defaults to email" class="input input-bordered input-sm"/></label>
<div class="md:col-span-2"><button class="btn btn-primary btn-sm">Send invitation</button></div>
</form></div></div>{back}"##,
            cname = html_escape(&cname),
            id = id,
            back = back,
        )
    };
    portal_admin_shell(&user, "Portal Users", &inner).into_response()
}

/// Look up a valid (unconsumed, unexpired) invite by raw token → its user id.
async fn portal_invite_lookup(db: &PgPool, token: &str) -> Option<uuid::Uuid> {
    let token_hash = hash_token(token);
    sqlx::query_scalar(
        "SELECT user_id FROM portal_invite \
         WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()",
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
}

fn portal_invite_page_html(token: &str, err: Option<&str>) -> String {
    use vortex_framework::ui::html_escape;
    let err_html = err
        .map(|e| format!(r#"<div class="alert alert-error text-sm mb-3">{}</div>"#, html_escape(e)))
        .unwrap_or_default();
    format!(
        r#"<!DOCTYPE html><html data-theme="dark"><head>
<title>Set your password</title><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<script src="/static/vendor/tailwind.js"></script>
<style>body{{background:#0b0f0a;color:#e5e7eb}}</style></head>
<body class="min-h-screen flex items-center justify-center p-4">
<div class="w-full max-w-sm" style="background:#12160f;border:1px solid #263019;border-radius:.75rem;padding:1.5rem">
  <div class="text-center mb-5"><div class="text-2xl font-bold"><span style="color:#8BC53F">re</span><span style="color:#9ca3af">micle</span></div>
  <div class="text-sm mt-1" style="color:#9ca3af">Set your portal password</div></div>
  {err_html}
  <form method="post" action="/portal/invite/{token}" class="flex flex-col gap-3">
    <label class="text-sm">New password
      <input name="password" type="password" required minlength="8" autocomplete="new-password" class="input input-bordered w-full mt-1" style="background:#0b0f0a"/>
    </label>
    <label class="text-sm">Confirm password
      <input name="confirm" type="password" required minlength="8" autocomplete="new-password" class="input input-bordered w-full mt-1" style="background:#0b0f0a"/>
    </label>
    <button class="btn mt-2" style="background:#8BC53F;border-color:#8BC53F;color:#000">Set password &amp; sign in</button>
  </form>
</div></body></html>"#,
        err_html = err_html,
        token = html_escape(token),
    )
}

/// Resolve the tenant pool for a public (pre-auth) portal request from the Host
/// header — the invite/login routes have no `DatabaseContext` injected.
async fn portal_public_pool(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<sqlx::PgPool, Response> {
    let db_name = resolve_database(state, headers, None).await;
    state
        .pool_manager
        .get_pool(&db_name)
        .await
        .map(|p| p.pool().clone())
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, Html("Service unavailable")).into_response())
}

async fn portal_invite_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let db = match portal_public_pool(&state, &headers).await {
        Ok(d) => d,
        Err(r) => return r,
    };
    if portal_invite_lookup(&db, &token).await.is_none() {
        let body = r#"<!DOCTYPE html><html data-theme="dark"><head><title>Invite</title><link href="/static/vendor/daisyui.min.css" rel="stylesheet"/><script src="/static/vendor/tailwind.js"></script><style>body{background:#0b0f0a;color:#e5e7eb}</style></head><body class="min-h-screen flex items-center justify-center p-4"><div class="text-center"><h1 class="text-xl font-bold mb-2">Invitation not valid</h1><p class="text-base-content/60">This invite link has expired or already been used. Ask your account manager to resend it.</p></div></body></html>"#;
        return (StatusCode::NOT_FOUND, Html(body)).into_response();
    }
    Html(portal_invite_page_html(&token, None)).into_response()
}

#[derive(serde::Deserialize)]
struct PortalInviteAccept {
    password: String,
    confirm: String,
}

async fn portal_invite_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Form(form): Form<PortalInviteAccept>,
) -> Response {
    let db = match portal_public_pool(&state, &headers).await {
        Ok(d) => d,
        Err(r) => return r,
    };
    let Some(user_id) = portal_invite_lookup(&db, &token).await else {
        return (StatusCode::NOT_FOUND, Html(portal_invite_page_html(&token, Some("This invite is no longer valid.")))).into_response();
    };
    if form.password.len() < 8 {
        return Html(portal_invite_page_html(&token, Some("Password must be at least 8 characters."))).into_response();
    }
    if form.password != form.confirm {
        return Html(portal_invite_page_html(&token, Some("Passwords don't match."))).into_response();
    }
    let hash = hash_password(&form.password);
    // Activate the account and consume the token in one go. Re-check is_portal
    // defensively so this can only ever activate a portal login.
    let updated = sqlx::query(
        "UPDATE users SET password_hash = $1, active = true, must_change_password = false, \
                password_changed_at = NOW() WHERE id = $2 AND is_portal = true",
    )
    .bind(&hash)
    .bind(user_id)
    .execute(&db)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0);
    if updated == 0 {
        return (StatusCode::NOT_FOUND, Html(portal_invite_page_html(&token, Some("This invite is no longer valid.")))).into_response();
    }
    let th = hash_token(&token);
    let _ = sqlx::query("UPDATE portal_invite SET consumed_at = NOW() WHERE token_hash = $1")
        .bind(&th).execute(&db).await;
    Redirect::to("/portal/login").into_response()
}

// NOTE: error_response / forbidden_page moved to vortex_framework::ui

#[derive(sqlx::FromRow)]
struct UserRow {
    id: uuid::Uuid,
    username: String,
    password_hash: String,
    full_name: Option<String>,
    active: bool,
    locked: bool,
}

/// Validates a SQL identifier (table/column name) is safe for interpolation.
/// Only allows lowercase letters, digits, underscores, and dots (for schema-qualified names).
fn validate_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
        && name.chars().next().map_or(false, |c| c.is_ascii_lowercase() || c == '_')
}

// NOTE: html_escape moved to vortex_framework::ui

/// Formats an integer with comma separators (e.g. 50064 → "50,064").
/// Middleware that adds OWASP-recommended security headers to all responses.
async fn security_headers_middleware(
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert("Referrer-Policy", "strict-origin-when-cross-origin".parse().unwrap());
    headers.insert("Permissions-Policy", "camera=(), microphone=(), geolocation=()".parse().unwrap());
    headers.insert(
        "Content-Security-Policy",
        // Self-contained by policy: all CSS/JS is vendored under
        // /static/vendor (no CDNs — air-gapped installs must render
        // correctly). The one external allowance is OpenStreetMap
        // tiles, which are runtime map data, not page assets; fully
        // air-gapped sites point Leaflet at a local tile server.
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: https://*.tile.openstreetmap.org; font-src 'self'".parse().unwrap(),
    );
    response
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    match PasswordHash::new(hash) {
        Ok(parsed_hash) => {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
        }
        Err(_) => false,
    }
}

fn generate_session_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.r#gen();
    hex::encode(bytes)
}

fn hash_token(token: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

async fn logout(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    // Revoke the session in database
    let _ = sqlx::query(
        "UPDATE sessions SET revoked = true, revoked_at = NOW(), revoked_reason = 'User logout' WHERE id = $1"
    )
    .bind(&user.session_id)
    .execute(&db)
    .await;

    // Log the logout through the WORM ledger.
    let audit_entry = AuditEntry::new(AuditAction::Logout, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_session(user.session_id)
        .with_resource("session", user.session_id.to_string())
        .with_details(serde_json::json!({
            "reason": "user_initiated",
        }));
    if let Err(e) = state.audit.log(audit_entry).await {
        error!("WORM audit write failed for Logout: {}", e);
    }

    info!("User {} logged out", user.username);

    // Clear the cookie and redirect to login.
    // Use a real HTTP 302 redirect so it works both from HTMX
    // (sidebar logout button) and from a direct browser hit
    // (typing /auth/logout in the address bar).
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".parse().unwrap(),
    );
    headers.insert(header::LOCATION, "/login".parse().unwrap());
    // Also send HX-Redirect so HTMX callers do a full-page
    // navigation instead of trying to swap into the current page.
    headers.insert("HX-Redirect", "/login".parse().unwrap());
    (StatusCode::FOUND, headers).into_response()
}

async fn home_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Html<String> {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("home", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    // Build condensed module links for the "Modules" section.
    // Contacts is now contributed by the plugin registry (below),
    // not hardcoded — removing the old inline link prevents the
    // duplicate entry.
    let mut module_links = String::new();
    // Plugin-contributed home tiles. The registry filters by install
    // state + role and returns menu entries; we render the top-level
    // Operations-group entries as home screen quick links.
    for entry in state.plugin_registry.collect_menu_by_group(
        vortex_framework::MenuGroup::Operations,
        &installed,
        &user.roles,
    ) {
        if entry.parent.is_none() {
            module_links.push_str(&format!(
                r##"<a href="{}" class="btn btn-ghost btn-sm justify-start gap-2"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" stroke-width="2" fill="none"/></svg>{}</a>"##,
                html_escape(&entry.url),
                html_escape(&entry.label)
            ));
        }
    }
    if user.is_admin() {
        module_links.push_str(r#"<a href="/users" class="btn btn-ghost btn-sm justify-start gap-2"><svg class="w-4 h-4 text-info" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m9 5.197v-1"/></svg>User Management</a>"#);
        module_links.push_str(r#"<a href="/settings" class="btn btn-ghost btn-sm justify-start gap-2"><svg class="w-4 h-4 text-neutral" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>Settings</a>"#);
        module_links.push_str(r#"<a href="/modules" class="btn btn-ghost btn-sm justify-start gap-2"><svg class="w-4 h-4 text-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>Modules</a>"#);
    }

    // Build the shortcuts modal HTML
    let shortcuts_modal = r#"<dialog id="shortcuts-modal" class="modal">
<div class="modal-box max-w-lg">
<h3 class="font-bold text-lg mb-4">Edit Shortcuts</h3>
<div role="tablist" class="tabs tabs-boxed mb-4">
<a role="tab" class="tab tab-active" onclick="showShortcutTab('menu')">From Menu</a>
<a role="tab" class="tab" onclick="showShortcutTab('custom')">Custom Link</a>
</div>
<div id="tab-menu">
<div id="available-shortcuts" class="space-y-1">Loading...</div>
</div>
<div id="tab-custom" style="display:none">
<div class="form-control mb-2"><label class="label label-text">Label</label><input id="custom-label" class="input input-bordered input-sm" placeholder="My Link"/></div>
<div class="form-control mb-3"><label class="label label-text">URL</label><input id="custom-url" class="input input-bordered input-sm" placeholder="/some/page"/></div>
<button class="btn btn-primary btn-sm" onclick="addCustomShortcut()">Add</button>
</div>
<div class="modal-action"><form method="dialog"><button class="btn btn-sm">Close</button></form></div>
</div>
</dialog>"#;

    // JavaScript for shortcuts modal - use string concatenation to avoid brace escaping issues
    let shortcuts_js = String::new()
        + "<script>"
        + "function showShortcutTab(tab){"
        + "document.getElementById('tab-menu').style.display=tab==='menu'?'':'none';"
        + "document.getElementById('tab-custom').style.display=tab==='custom'?'':'none';"
        + "document.querySelectorAll('.tabs .tab').forEach(function(t,i){"
        + "t.classList.toggle('tab-active',i===(tab==='menu'?0:1));"
        + "});"
        + "}"
        + "function loadAvailableShortcuts(){"
        + "fetch('/api/home/shortcuts/available').then(function(r){return r.json()}).then(function(d){"
        + "var html='';"
        + "d.items.forEach(function(item){"
        + "html+='<button class=\"btn btn-ghost btn-sm justify-start w-full\" '"
        + "+'onclick=\"addMenuShortcut(\\''+item.label+'\\',\\''+item.url+'\\',\\''+item.icon+'\\',\\''+item.color+'\\')\">'"
        + "+item.label+'</button>';"
        + "});"
        + "document.getElementById('available-shortcuts').innerHTML=html;"
        + "});"
        + "}"
        + "function addMenuShortcut(label,url,icon,color){"
        + "var form=new FormData();"
        + "form.append('label',label);form.append('url',url);form.append('icon',icon);form.append('color',color);"
        + "fetch('/api/home/shortcuts',{method:'POST',body:new URLSearchParams(form)}).then(function(r){return r.text()}).then(function(h){"
        + "document.getElementById('shortcuts-panel').innerHTML=h;"
        + "});"
        + "}"
        + "function addCustomShortcut(){"
        + "var label=document.getElementById('custom-label').value;"
        + "var url=document.getElementById('custom-url').value;"
        + "if(!label||!url)return;"
        + "var form=new FormData();"
        + "form.append('label',label);form.append('url',url);form.append('icon','link');form.append('color','primary');form.append('is_custom','true');"
        + "fetch('/api/home/shortcuts',{method:'POST',body:new URLSearchParams(form)}).then(function(r){return r.text()}).then(function(h){"
        + "document.getElementById('shortcuts-panel').innerHTML=h;"
        + "document.getElementById('custom-label').value='';"
        + "document.getElementById('custom-url').value='';"
        + "});"
        + "}"
        + "document.getElementById('shortcuts-modal').addEventListener('close',function(){});"
        + "document.getElementById('shortcuts-modal').addEventListener('show',loadAvailableShortcuts);"
        + "var origShow=HTMLDialogElement.prototype.showModal;"
        + "var modal=document.getElementById('shortcuts-modal');"
        + "var origFn=modal.showModal.bind(modal);"
        + "modal.showModal=function(){loadAvailableShortcuts();origFn();};"
        + "</script>";

    // Admin-only system overview — folded in from the retired /dashboard.
    // Live counts (the old dashboard tiles were hardcoded) plus the same
    // recent-activity / system-status partials the dashboard used.
    let admin_overview = if user.is_admin() {
        let active_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE active = true")
            .fetch_one(&db).await.unwrap_or(0);
        let companies: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM companies")
            .fetch_one(&db).await.unwrap_or(0);
        let modules = installed.len();
        let audit_24h: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE timestamp > NOW() - INTERVAL '24 hours'")
            .fetch_one(&db).await.unwrap_or(0);
        format!(
            r#"<div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">Active Users</div><div class="stat-value text-primary">{au}</div></div>
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">Companies</div><div class="stat-value text-secondary">{co}</div></div>
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">Modules</div><div class="stat-value text-accent">{mo}</div></div>
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">Audit Events</div><div class="stat-value text-info">{ae}</div><div class="stat-desc">Last 24h</div></div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="card-title text-lg">Recent Activity</h2><div class="overflow-x-auto" hx-get="/partials/recent-activity" hx-trigger="load" hx-swap="innerHTML"><span class="loading loading-spinner loading-sm"></span></div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="card-title text-lg">System Status</h2><div hx-get="/partials/system-status" hx-trigger="load" hx-swap="innerHTML"><span class="loading loading-spinner loading-sm"></span></div></div></div>
</div>"#,
            au = active_users, co = companies, mo = modules, ae = audit_24h
        )
    } else {
        String::new()
    };

    let html = format!(
        r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Home - Remicle</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script>
<script src="/static/vendor/htmx.min.js"></script>
</head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="mb-6"><h1 class="text-2xl font-bold">Welcome, {display_name}</h1><p class="text-base-content/60">Here's what's happening today</p></div>

{admin_overview}
<!-- Announcements (full width) -->
<div class="card bg-base-100 shadow mb-6">
<div class="card-body">
<h2 class="card-title text-lg"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z"/></svg>Announcements</h2>
<div id="announcements-panel" hx-get="/partials/home/announcements" hx-trigger="load" hx-swap="innerHTML"><span class="loading loading-spinner loading-sm"></span></div>
</div></div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
<!-- Left column: Shortcuts + Discussion -->
<div class="lg:col-span-2 space-y-6">

<!-- My Shortcuts -->
<div class="card bg-base-100 shadow">
<div class="card-body">
<h2 class="card-title text-lg"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>My Shortcuts</h2>
<div id="shortcuts-panel" hx-get="/partials/home/shortcuts" hx-trigger="load" hx-swap="innerHTML"><span class="loading loading-spinner loading-sm"></span></div>
</div></div>

<!-- My Calendar -->
<div class="card bg-base-100 shadow">
<div class="card-body">
<h2 class="card-title text-lg"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>My Calendar</h2>
<div id="calendar-panel" hx-get="/partials/home/calendar" hx-trigger="load" hx-swap="innerHTML"><span class="loading loading-spinner loading-sm"></span></div>
</div></div>

</div>

<!-- Right column: Activities + Modules -->
<div class="space-y-6">

<!-- My Activities -->
<div class="card bg-base-100 shadow">
<div class="card-body">
<h2 class="card-title text-lg"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>My Activities</h2>
<div id="activities-panel" hx-get="/partials/home/activities" hx-trigger="load" hx-swap="innerHTML"><span class="loading loading-spinner loading-sm"></span></div>
</div></div>

<!-- Modules -->
<div class="card bg-base-100 shadow">
<div class="card-body">
<h2 class="card-title text-lg"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>Modules</h2>
<div class="flex flex-col gap-1">{module_links}</div>
</div></div>

</div></div>
{shortcuts_modal}
</main></div>
{shortcuts_js}
</body></html>"#,
        sidebar = sidebar,
        display_name = html_escape(display_name),
        admin_overview = admin_overview,
        module_links = module_links,
        shortcuts_modal = shortcuts_modal,
        shortcuts_js = shortcuts_js,
    );

    Html(html)
}

// NOTE: get_initials moved to vortex_framework::ui


async fn recent_activity(State(state): State<Arc<AppState>>, Db(db): Db) -> Html<String> {
    // Fetch recent audit log entries for the UI. This is a read-only view
    // over the WORM ledger and is intentionally decoupled from the
    // `vortex_security::AuditEntry` struct — it only needs a few columns
    // for rendering, and stays compatible with pre-chain legacy rows.
    let entries = sqlx::query_as::<_, AuditActivityRow>(
        r#"
        SELECT
            timestamp,
            COALESCE(username, 'System') as username,
            action,
            COALESCE(resource_type, 'system') as resource_type
        FROM audit_log
        ORDER BY timestamp DESC
        LIMIT 10
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let rows: String = entries
        .iter()
        .map(|e| {
            let time_ago = format_time_ago(e.timestamp);
            let badge_class = match e.action.as_str() {
                // New chained-ledger codes
                "login_success" => "badge-info",
                "login_failure" => "badge-error",
                "logout" => "badge-warning",
                "user_created" | "user_updated" | "user_unlocked" => "badge-info",
                "chain_verification_passed" => "badge-success",
                "chain_verification_failed" | "trigger_disabled" => "badge-error",
                // Legacy pre-chain rows
                "LOGIN" => "badge-info",
                "LOGIN_FAILED" => "badge-error",
                "LOGOUT" => "badge-warning",
                "SYSTEM_INITIALIZED" | "AUDIT_WORM_ENABLED" => "badge-success",
                _ => "badge-neutral",
            };
            format!(
                r#"<tr>
                    <td class="text-base-content/60">{}</td>
                    <td>{}</td>
                    <td><span class="badge {} badge-sm">{}</span></td>
                    <td>{}</td>
                </tr>"#,
                time_ago, e.username, badge_class, e.action, e.resource_type
            )
        })
        .collect();

    Html(format!(
        r#"<table class="table table-sm">
            <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Resource</th></tr></thead>
            <tbody>{}</tbody>
        </table>"#,
        rows
    ))
}

#[derive(sqlx::FromRow)]
struct AuditActivityRow {
    timestamp: chrono::DateTime<chrono::Utc>,
    username: String,
    action: String,
    resource_type: String,
}

// NOTE: format_time_ago moved to vortex_framework::ui

async fn system_status(State(state): State<Arc<AppState>>, Db(db): Db) -> Html<String> {
    // Get real stats from database
    let session_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE expires_at > NOW() AND NOT revoked"
    )
    .fetch_one(&db)
    .await
    .unwrap_or(0);

    let user_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE active = true"
    )
    .fetch_one(&db)
    .await
    .unwrap_or(0);

    Html(format!(
        r#"<div class="space-y-3">
            <div class="flex items-center justify-between">
                <span>Database</span>
                <span class="badge badge-success">Connected</span>
            </div>
            <div class="flex items-center justify-between">
                <span>Active Users</span>
                <span class="badge badge-info">{}</span>
            </div>
            <div class="flex items-center justify-between">
                <span>Active Sessions</span>
                <span class="badge badge-info">{}</span>
            </div>
            <div class="flex items-center justify-between">
                <span>Audit Ledger</span>
                <span class="badge badge-success">Sealed</span>
            </div>
        </div>"#,
        user_count, session_count
    ))
}

// =============================================================================
// HOME SCREEN: Partials, Announcements CRUD, Shortcuts
// =============================================================================

/// Map a chatter res_model to a URL for linking activities back to
/// their source record. The core only knows about core models (contacts,
/// users, companies). Plugin models are expected to route via generic
/// `/list/{model}/{id}` — plugins that want custom URL patterns should
/// contribute a URL-mapper hook in a future phase.
fn model_to_url(res_model: &str, res_id: &uuid::Uuid) -> Option<String> {
    match res_model {
        "contacts" => Some(format!("/contacts/{}", res_id)),
        _ => None,
    }
}

/// HTMX partial: announcements panel for the home screen
async fn home_announcements_partial(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Html<String> {
    let company_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT company_id FROM users WHERE id = $1"
    )
    .bind(user.id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let company_id = match company_id {
        Some(c) => c,
        None => return Html(r#"<div class="text-base-content/50 text-sm">No company assigned.</div>"#.to_string()),
    };

    let rows = sqlx::query(
        "SELECT a.id, a.title, a.body, a.severity, a.is_pinned, a.created_at,
                u.full_name as author_name
         FROM announcements a
         LEFT JOIN users u ON a.created_by = u.id
         WHERE a.company_id = $1 AND a.active = true
           AND (a.publish_at IS NULL OR a.publish_at <= NOW())
           AND (a.expire_at IS NULL OR a.expire_at > NOW())
         ORDER BY a.is_pinned DESC, a.created_at DESC LIMIT 5"
    )
    .bind(company_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    if rows.is_empty() {
        let admin_link = if user.is_admin() {
            r#" <a href="/announcements/new" class="link link-primary text-sm">Create one</a>"#
        } else {
            ""
        };
        return Html(format!(
            r#"<div class="text-base-content/50 text-sm py-4">No announcements yet.{}</div>"#,
            admin_link
        ));
    }

    let mut html = String::new();
    for row in &rows {
        let title: String = row.get("title");
        let body: String = row.get("body");
        let severity: String = row.get("severity");
        let is_pinned: bool = row.get("is_pinned");
        let author: Option<String> = row.get("author_name");
        let created: chrono::DateTime<chrono::Utc> = row.get("created_at");

        let alert_class = match severity.as_str() {
            "success" => "alert-success",
            "warning" => "alert-warning",
            "error" => "alert-error",
            _ => "alert-info",
        };
        let pin_icon = if is_pinned {
            r#"<svg class="w-4 h-4 inline mr-1" fill="currentColor" viewBox="0 0 20 20"><path d="M5 5a2 2 0 012-2h6a2 2 0 012 2v2h2a1 1 0 01.8 1.6L15 12v3a1 1 0 01-1 1h-3v3a1 1 0 11-2 0v-3H6a1 1 0 01-1-1v-3L2.2 8.6A1 1 0 013 7h2V5z"/></svg>"#
        } else {
            ""
        };

        html.push_str(&format!(
            r#"<div class="alert {} shadow-sm mb-2"><div><div class="font-semibold">{}{}</div><div class="text-sm opacity-80">{}</div><div class="text-xs opacity-50 mt-1">by {} &middot; {}</div></div></div>"#,
            alert_class,
            pin_icon,
            html_escape(&title),
            html_escape(&body),
            html_escape(&author.unwrap_or_else(|| "System".into())),
            format_time_ago(created),
        ));
    }

    if user.is_admin() {
        html.push_str(r#"<div class="mt-2"><a href="/announcements" class="link link-primary text-sm">Manage Announcements</a></div>"#);
    }

    Html(html)
}

/// HTMX partial: user shortcuts panel for the home screen
async fn home_shortcuts_partial(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Html<String> {
    let rows = sqlx::query(
        "SELECT id, label, url, icon, color, is_custom
         FROM user_shortcuts
         WHERE user_id = $1 AND active = true
         ORDER BY sequence ASC LIMIT 12"
    )
    .bind(user.id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    if rows.is_empty() {
        return Html(r#"<div class="text-center py-6"><p class="text-base-content/50 text-sm mb-3">Add shortcuts to quickly access your most-used pages.</p><button class="btn btn-sm btn-outline btn-primary" onclick="document.getElementById('shortcuts-modal').showModal()">+ Add Shortcut</button></div>"#.to_string());
    }

    let mut html = String::from(r#"<div class="grid grid-cols-2 sm:grid-cols-3 gap-2">"#);
    for row in &rows {
        let label: String = row.get("label");
        let url: String = row.get("url");
        let icon: Option<String> = row.get("icon");
        let color: Option<String> = row.get("color");
        let _icon_name = icon.as_deref().unwrap_or("link");
        let color_name = color.as_deref().unwrap_or("primary");

        html.push_str(&format!(
            r#"<a href="{}" class="btn btn-ghost btn-sm justify-start gap-2 border border-base-300 hover:border-{}"><svg class="w-4 h-4 text-{}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg><span class="truncate">{}</span></a>"#,
            html_escape(&url),
            color_name,
            color_name,
            html_escape(&label),
        ));
    }
    html.push_str("</div>");
    html.push_str(r#"<div class="mt-2 text-right"><button class="btn btn-xs btn-ghost" onclick="document.getElementById('shortcuts-modal').showModal()">Edit Shortcuts</button></div>"#);

    Html(html)
}

/// HTMX partial: activities panel for the home screen
async fn home_activities_partial(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Html<String> {
    let rows = sqlx::query(
        "SELECT a.id, a.summary, a.due_date, a.state, a.res_model, a.res_id,
                t.name as type_name, t.icon, t.color
         FROM chatter_activities a
         LEFT JOIN chatter_activity_types t ON a.activity_type_id = t.id
         WHERE a.assigned_to_id = $1 AND a.state IN ('pending','overdue') AND a.active = true
         ORDER BY CASE WHEN a.state='overdue' THEN 0 ELSE 1 END, a.due_date ASC
         LIMIT 20"
    )
    .bind(user.id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    if rows.is_empty() {
        return Html(r#"<div class="text-center py-6 text-base-content/50 text-sm">No pending activities. You're all caught up!</div>"#.to_string());
    }

    let mut html = String::from(r#"<div class="space-y-2">"#);
    for row in &rows {
        let activity_id: uuid::Uuid = row.get("id");
        let summary: Option<String> = row.get("summary");
        let due_date: chrono::NaiveDate = row.get("due_date");
        let state: String = row.get("state");
        let res_model: String = row.get("res_model");
        let res_id: uuid::Uuid = row.get("res_id");
        let type_name: Option<String> = row.get("type_name");
        let color: Option<String> = row.get("color");

        let badge_class = if state == "overdue" { "badge-error" } else { "badge-warning" };
        let badge_text = if state == "overdue" { "Overdue" } else { "Pending" };
        let color_val = color.as_deref().unwrap_or("primary");

        let link = model_to_url(&res_model, &res_id);
        let summary_text = summary.as_deref().unwrap_or("(no summary)");
        let type_label = type_name.as_deref().unwrap_or("Activity");

        let summary_html = if let Some(ref href) = link {
            format!(r#"<a href="{}" class="link link-hover font-medium">{}</a>"#, href, html_escape(summary_text))
        } else {
            format!(r#"<span class="font-medium">{}</span>"#, html_escape(summary_text))
        };

        let complete_url = format!("/api/chatter/{}/{}/activities/{}/complete", html_escape(&res_model), res_id, activity_id);
        html.push_str("<div class=\"flex items-center gap-3 p-2 rounded-lg hover:bg-base-200\">");
        html.push_str(&format!("<div class=\"badge badge-sm badge-outline text-{}\">{}</div>", color_val, html_escape(type_label)));
        html.push_str(&format!("<div class=\"flex-1 min-w-0\">{}<div class=\"text-xs text-base-content/50\">Due: {} <span class=\"badge {} badge-xs\">{}</span></div></div>", summary_html, due_date, badge_class, badge_text));
        html.push_str("<button class=\"btn btn-xs btn-success\" hx-post=\"");
        html.push_str(&complete_url);
        html.push_str("\" hx-target=\"#activities-panel\" hx-swap=\"innerHTML\" hx-get=\"/partials/home/activities\" hx-trigger=\"click\" title=\"Mark Done\">Done</button>");
        html.push_str("</div>");
    }
    html.push_str("</div>");

    Html(html)
}

// -- Home Calendar partial (replaces dead Discussion feed) --------------------

/// Default entry: current month
async fn home_calendar_partial(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Html<String> {
    let now = chrono::Utc::now();
    build_home_calendar(&db, &user, now.year(), now.month()).await
}

/// Parameterized entry: specific year/month
async fn home_calendar_partial_month(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((year, month)): Path<(i32, u32)>,
) -> Html<String> {
    let month = month.clamp(1, 12);
    build_home_calendar(&db, &user, year, month).await
}

/// Calendar event sourced from one of three tables
struct CalendarEvent {
    label: String,
    url: Option<String>,
    /// CSS class for the dot: bg-error, bg-warning, bg-info, bg-success
    color_class: &'static str,
    sort_key: u8,
}

async fn build_home_calendar(
    db: &sqlx::PgPool,
    user: &AuthUser,
    year: i32,
    month: u32,
) -> Html<String> {
    let first_day = chrono::NaiveDate::from_ymd_opt(year, month, 1).unwrap();
    let last_day = if month == 12 {
        chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap().pred_opt().unwrap()
    } else {
        chrono::NaiveDate::from_ymd_opt(year, month + 1, 1).unwrap().pred_opt().unwrap()
    };

    let mut events_by_date: std::collections::HashMap<chrono::NaiveDate, Vec<CalendarEvent>> =
        std::collections::HashMap::new();

    // 1) Activities (pending / overdue) assigned to this user
    let act_rows = sqlx::query(
        "SELECT a.summary, a.due_date, a.state, a.res_model, a.res_id
         FROM chatter_activities a
         WHERE a.assigned_to_id = $1 AND a.state IN ('pending','overdue') AND a.active = true
           AND a.due_date >= $2 AND a.due_date <= $3
         ORDER BY a.due_date"
    )
    .bind(user.id)
    .bind(first_day)
    .bind(last_day)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    for row in &act_rows {
        let date: chrono::NaiveDate = row.get("due_date");
        let state: String = row.get("state");
        let summary: Option<String> = row.get("summary");
        let res_model: String = row.get("res_model");
        let res_id: uuid::Uuid = row.get("res_id");
        let (color_class, sort_key) = if state == "overdue" {
            ("bg-error", 0u8)
        } else {
            ("bg-warning", 1)
        };
        events_by_date.entry(date).or_default().push(CalendarEvent {
            label: summary.unwrap_or_else(|| "Activity".to_string()),
            url: model_to_url(&res_model, &res_id),
            color_class,
            sort_key,
        });
    }

    // Note: plugin-specific calendar events are no longer hardcoded
    // here. A future phase will add a
    // `Plugin::calendar_events` hook so plugins can contribute their
    // own events to the home calendar. The core calendar shows only
    // mail.activity items from the chatter subsystem.
    let _ = (user.id, first_day, last_day, db); // silence unused

    // Sort events within each day by priority
    for events in events_by_date.values_mut() {
        events.sort_by_key(|e| e.sort_key);
    }

    // Build calendar grid
    let weekday_of_first = first_day.weekday().num_days_from_sunday();
    let days_in_month = last_day.day();
    let today = chrono::Utc::now().date_naive();

    let mut cells = String::new();

    // Empty leading cells
    for _ in 0..weekday_of_first {
        cells.push_str(r#"<div class="min-h-[3.5rem] bg-base-200/30 rounded"></div>"#);
    }

    // Day cells
    for day in 1..=days_in_month {
        let date = chrono::NaiveDate::from_ymd_opt(year, month, day).unwrap();
        let is_today = date == today;
        let ring = if is_today { " ring-2 ring-primary" } else { "" };
        let day_color = if is_today { " text-primary font-bold" } else { "" };

        cells.push_str(&format!(
            "<div class=\"min-h-[3.5rem] bg-base-100 p-1 border border-base-300 rounded{}\">",
            ring
        ));
        cells.push_str(&format!("<div class=\"text-xs{}\">{}</div>", day_color, day));

        if let Some(events) = events_by_date.get(&date) {
            cells.push_str("<div class=\"flex flex-wrap gap-0.5 mt-0.5\">");
            let show = events.len().min(3);
            for ev in events.iter().take(show) {
                if let Some(ref href) = ev.url {
                    cells.push_str(&format!(
                        "<a href=\"{}\" class=\"w-2 h-2 rounded-full {} hover:ring-1 ring-white\" title=\"{}\"></a>",
                        html_escape(href),
                        ev.color_class,
                        html_escape(&ev.label)
                    ));
                } else {
                    cells.push_str(&format!(
                        "<span class=\"w-2 h-2 rounded-full {}\" title=\"{}\"></span>",
                        ev.color_class,
                        html_escape(&ev.label)
                    ));
                }
            }
            if events.len() > 3 {
                cells.push_str(&format!(
                    "<span class=\"text-[0.6rem] text-base-content/50\">+{}</span>",
                    events.len() - 3
                ));
            }
            cells.push_str("</div>");
        }
        cells.push_str("</div>");
    }

    // Trailing empty cells
    let total_cells = weekday_of_first + days_in_month;
    let remaining = (7 - (total_cells % 7)) % 7;
    for _ in 0..remaining {
        cells.push_str(r#"<div class="min-h-[3.5rem] bg-base-200/30 rounded"></div>"#);
    }

    // Navigation
    let (prev_year, prev_month) = if month == 1 { (year - 1, 12u32) } else { (year, month - 1) };
    let (next_year, next_month) = if month == 12 { (year + 1, 1u32) } else { (year, month + 1) };

    let month_names = ["", "January", "February", "March", "April", "May", "June",
                       "July", "August", "September", "October", "November", "December"];
    let month_name = month_names[month as usize];

    let mut html = String::with_capacity(4096);
    // Nav bar
    html.push_str("<div class=\"flex items-center justify-between mb-3\">");
    html.push_str(&format!(
        "<button class=\"btn btn-ghost btn-xs\" hx-get=\"/partials/home/calendar/{}/{}\" hx-target=\"#calendar-panel\" hx-swap=\"innerHTML\">&larr;</button>",
        prev_year, prev_month
    ));
    html.push_str(&format!("<span class=\"font-semibold text-sm\">{} {}</span>", month_name, year));
    html.push_str(&format!(
        "<button class=\"btn btn-ghost btn-xs\" hx-get=\"/partials/home/calendar/{}/{}\" hx-target=\"#calendar-panel\" hx-swap=\"innerHTML\">&rarr;</button>",
        next_year, next_month
    ));
    html.push_str("</div>");

    // Day-of-week header
    html.push_str("<div class=\"grid grid-cols-7 gap-px text-center text-xs font-semibold text-base-content/60 mb-1\">");
    for d in &["Sun","Mon","Tue","Wed","Thu","Fri","Sat"] {
        html.push_str(&format!("<div>{}</div>", d));
    }
    html.push_str("</div>");

    // Calendar grid
    html.push_str("<div class=\"grid grid-cols-7 gap-px\">");
    html.push_str(&cells);
    html.push_str("</div>");

    // Legend
    html.push_str("<div class=\"flex flex-wrap gap-3 mt-3 text-xs text-base-content/60\">");
    html.push_str("<span class=\"flex items-center gap-1\"><span class=\"w-2 h-2 rounded-full bg-error\"></span>Overdue</span>");
    html.push_str("<span class=\"flex items-center gap-1\"><span class=\"w-2 h-2 rounded-full bg-warning\"></span>Activity</span>");
    html.push_str("<span class=\"flex items-center gap-1\"><span class=\"w-2 h-2 rounded-full bg-info\"></span>Task</span>");
    html.push_str("<span class=\"flex items-center gap-1\"><span class=\"w-2 h-2 rounded-full bg-success\"></span>Review</span>");
    html.push_str("</div>");

    Html(html)
}

// -- Announcement CRUD (admin-only) -------------------------------------------

#[derive(serde::Deserialize)]
struct AnnouncementForm {
    title: String,
    body: String,
    severity: Option<String>,
    is_pinned: Option<String>,
    publish_at: Option<String>,
    expire_at: Option<String>,
}

async fn announcements_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Announcements"))).into_response();
    }

    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("home", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    let rows = sqlx::query(
        "SELECT a.id, a.title, a.severity, a.is_pinned, a.active, a.created_at,
                u.full_name as author_name
         FROM announcements a
         LEFT JOIN users u ON a.created_by = u.id
         ORDER BY a.created_at DESC LIMIT 50"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let title: String = row.get("title");
        let severity: String = row.get("severity");
        let is_pinned: bool = row.get("is_pinned");
        let active: bool = row.get("active");
        let created: chrono::DateTime<chrono::Utc> = row.get("created_at");
        let author: Option<String> = row.get("author_name");

        let sev_badge = match severity.as_str() {
            "success" => r#"<span class="badge badge-success badge-sm">Success</span>"#,
            "warning" => r#"<span class="badge badge-warning badge-sm">Warning</span>"#,
            "error" => r#"<span class="badge badge-error badge-sm">Error</span>"#,
            _ => r#"<span class="badge badge-info badge-sm">Info</span>"#,
        };
        let pin_text = if is_pinned { "📌" } else { "" };
        let status = if active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else {
            r#"<span class="badge badge-ghost badge-sm">Archived</span>"#
        };

        table_rows.push_str(&format!(
            r#"<tr class="hover"><td>{pin}{title}</td><td>{sev}</td><td>{status}</td><td>{author}</td><td>{created}</td><td><a href="/announcements/{id}/edit" class="btn btn-xs btn-ghost">Edit</a><form method="POST" action="/announcements/{id}/delete" class="inline"><button class="btn btn-xs btn-ghost text-error">Delete</button></form></td></tr>"#,
            pin = pin_text,
            title = html_escape(&title),
            sev = sev_badge,
            status = status,
            author = html_escape(&author.unwrap_or_default()),
            created = format_time_ago(created),
            id = id,
        ));
    }

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Announcements - Remicle</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6">
<div><h1 class="text-2xl font-bold">Announcements</h1><p class="text-base-content/60">Manage company announcements shown on the home screen</p></div>
<a href="/announcements/new" class="btn btn-primary">+ New Announcement</a>
</div>
<div class="card bg-base-100 shadow"><div class="overflow-x-auto">
<table class="table table-sm"><thead><tr><th>Title</th><th>Severity</th><th>Status</th><th>Author</th><th>Created</th><th>Actions</th></tr></thead>
<tbody>{table_rows}</tbody></table></div></div>
</main></div></body></html>"#)).into_response()
}

async fn announcement_new(
    State(state): State<Arc<AppState>>,
    Db(_db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Announcements"))).into_response();
    }

    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("home", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>New Announcement - Remicle</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0"><h1 class="text-2xl font-bold mb-6">New Announcement</h1>
<form action="/announcements" method="POST" class="card bg-base-100 shadow p-6 max-w-2xl">
<div class="form-control mb-4"><label class="label"><span class="label-text">Title *</span></label><input name="title" class="input input-bordered" required/></div>
<div class="form-control mb-4"><label class="label"><span class="label-text">Body *</span></label><textarea name="body" class="textarea textarea-bordered h-32" required></textarea></div>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
<div class="form-control"><label class="label"><span class="label-text">Severity</span></label><select name="severity" class="select select-bordered"><option value="info">Info</option><option value="success">Success</option><option value="warning">Warning</option><option value="error">Error</option></select></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-2"><span class="label-text">Pinned</span><input type="checkbox" name="is_pinned" value="on" class="checkbox checkbox-primary"/></label></div>
</div>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
<div class="form-control"><label class="label"><span class="label-text">Publish At (leave empty for immediate)</span></label><input name="publish_at" type="datetime-local" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Expire At (leave empty for never)</span></label><input name="expire_at" type="datetime-local" class="input input-bordered"/></div>
</div>
<div class="flex gap-2 mt-4"><a href="/announcements" class="btn btn-ghost">Cancel</a><button class="btn btn-primary">Create Announcement</button></div>
</form></main></div></body></html>"#)).into_response()
}

async fn announcement_create(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<AnnouncementForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Announcements"))).into_response();
    }

    let company_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_optional(&db).await.ok().flatten();
    let company_id = match company_id {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "No company assigned").into_response(),
    };

    let severity = form.severity.as_deref().unwrap_or("info");
    let is_pinned = form.is_pinned.as_deref() == Some("on");
    let publish_at: Option<chrono::DateTime<chrono::Utc>> = form.publish_at.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M").ok())
        .map(|dt| dt.and_utc());
    let expire_at: Option<chrono::DateTime<chrono::Utc>> = form.expire_at.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M").ok())
        .map(|dt| dt.and_utc());

    let result = sqlx::query(
        "INSERT INTO announcements (title, body, severity, is_pinned, publish_at, expire_at, company_id, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"
    )
    .bind(&form.title)
    .bind(&form.body)
    .bind(severity)
    .bind(is_pinned)
    .bind(publish_at)
    .bind(expire_at)
    .bind(company_id)
    .bind(user.id)
    .execute(&db)
    .await;

    match result {
        Ok(_) => Redirect::to("/announcements").into_response(),
        Err(e) => {
            error!("Failed to create announcement: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {}", e)).into_response()
        }
    }
}

async fn announcement_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Announcements"))).into_response();
    }

    let row = sqlx::query("SELECT id, title, body, severity, is_pinned, publish_at, expire_at FROM announcements WHERE id = $1")
        .bind(id).fetch_optional(&db).await.ok().flatten();
    let row = match row {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "Announcement not found").into_response(),
    };

    let title: String = row.get("title");
    let body: String = row.get("body");
    let severity: String = row.get("severity");
    let is_pinned: bool = row.get("is_pinned");
    let publish_at: Option<chrono::DateTime<chrono::Utc>> = row.get("publish_at");
    let expire_at: Option<chrono::DateTime<chrono::Utc>> = row.get("expire_at");

    let pinned_checked = if is_pinned { "checked" } else { "" };
    let publish_val = publish_at.map(|d| d.format("%Y-%m-%dT%H:%M").to_string()).unwrap_or_default();
    let expire_val = expire_at.map(|d| d.format("%Y-%m-%dT%H:%M").to_string()).unwrap_or_default();

    let sev_options = ["info", "success", "warning", "error"].iter().map(|s| {
        let selected = if *s == severity.as_str() { "selected" } else { "" };
        format!(r#"<option value="{}" {}>{}</option>"#, s, selected, s.to_uppercase().chars().next().unwrap().to_string() + &s[1..])
    }).collect::<String>();

    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("home", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Edit Announcement - Remicle</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0"><h1 class="text-2xl font-bold mb-6">Edit Announcement</h1>
<form action="/announcements/{id}" method="POST" class="card bg-base-100 shadow p-6 max-w-2xl">
<div class="form-control mb-4"><label class="label"><span class="label-text">Title *</span></label><input name="title" class="input input-bordered" value="{title}" required/></div>
<div class="form-control mb-4"><label class="label"><span class="label-text">Body *</span></label><textarea name="body" class="textarea textarea-bordered h-32" required>{body}</textarea></div>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
<div class="form-control"><label class="label"><span class="label-text">Severity</span></label><select name="severity" class="select select-bordered">{sev_options}</select></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-2"><span class="label-text">Pinned</span><input type="checkbox" name="is_pinned" value="on" class="checkbox checkbox-primary" {pinned_checked}/></label></div>
</div>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
<div class="form-control"><label class="label"><span class="label-text">Publish At</span></label><input name="publish_at" type="datetime-local" class="input input-bordered" value="{publish_val}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Expire At</span></label><input name="expire_at" type="datetime-local" class="input input-bordered" value="{expire_val}"/></div>
</div>
<div class="flex gap-2 mt-4"><a href="/announcements" class="btn btn-ghost">Cancel</a><button class="btn btn-primary">Save Changes</button></div>
</form></main></div></body></html>"#,
        id = id,
        title = html_escape(&title),
        body = html_escape(&body),
        sev_options = sev_options,
        pinned_checked = pinned_checked,
        publish_val = publish_val,
        expire_val = expire_val,
    )).into_response()
}

async fn announcement_update(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<AnnouncementForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Announcements"))).into_response();
    }

    let severity = form.severity.as_deref().unwrap_or("info");
    let is_pinned = form.is_pinned.as_deref() == Some("on");
    let publish_at: Option<chrono::DateTime<chrono::Utc>> = form.publish_at.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M").ok())
        .map(|dt| dt.and_utc());
    let expire_at: Option<chrono::DateTime<chrono::Utc>> = form.expire_at.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M").ok())
        .map(|dt| dt.and_utc());

    let result = sqlx::query(
        "UPDATE announcements SET title=$1, body=$2, severity=$3, is_pinned=$4, publish_at=$5, expire_at=$6, updated_by=$7, updated_at=NOW() WHERE id=$8"
    )
    .bind(&form.title)
    .bind(&form.body)
    .bind(severity)
    .bind(is_pinned)
    .bind(publish_at)
    .bind(expire_at)
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await;

    match result {
        Ok(_) => Redirect::to("/announcements").into_response(),
        Err(e) => {
            error!("Failed to update announcement: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {}", e)).into_response()
        }
    }
}

async fn announcement_delete(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Announcements"))).into_response();
    }

    let _ = sqlx::query("UPDATE announcements SET active = false, updated_by = $1, updated_at = NOW() WHERE id = $2")
        .bind(user.id).bind(id).execute(&db).await;

    Redirect::to("/announcements").into_response()
}

// -- Shortcut management handlers ---------------------------------------------

#[derive(serde::Deserialize)]
struct ShortcutAddForm {
    label: String,
    url: String,
    icon: Option<String>,
    color: Option<String>,
    is_custom: Option<String>,
}

#[derive(serde::Deserialize)]
struct ShortcutReorderForm {
    ids: String, // comma-separated UUIDs
}

async fn shortcuts_available(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Json<serde_json::Value> {
    let installed = &db_ctx.installed_modules;
    let mut items = vec![];

    // Always-available core items
    items.push(serde_json::json!({"label": "Users", "url": "/users", "icon": "users", "color": "info"}));
    items.push(serde_json::json!({"label": "Settings", "url": "/settings", "icon": "settings", "color": "neutral"}));
    items.push(serde_json::json!({"label": "Modules", "url": "/modules", "icon": "package", "color": "accent"}));

    // Contacts is now contributed by the plugin registry (below),
    // not hardcoded — removing the old inline entry prevents duplicates.

    // Plugin-contributed shortcut candidates. The registry aggregates
    // Operations-group menu entries from every installed plugin and we
    // expose them as pickable shortcuts with a neutral colour.
    for entry in state.plugin_registry.collect_menu_by_group(
        vortex_framework::MenuGroup::Operations,
        installed,
        &user.roles,
    ) {
        items.push(serde_json::json!({
            "label": entry.label,
            "url": entry.url,
            "icon": entry.icon.unwrap_or_else(|| "square".to_string()),
            "color": "warning",
        }));
    }

    Json(serde_json::json!({"items": items}))
}

async fn shortcut_add(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<ShortcutAddForm>,
) -> Response {
    let company_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_optional(&db).await.ok().flatten();
    let company_id = match company_id {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "No company assigned").into_response(),
    };

    // Get next sequence
    let max_seq: Option<i32> = sqlx::query_scalar(
        "SELECT MAX(sequence) FROM user_shortcuts WHERE user_id = $1 AND active = true"
    )
    .bind(user.id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let next_seq = max_seq.unwrap_or(0) + 10;

    let is_custom = form.is_custom.as_deref() == Some("true");

    let _ = sqlx::query(
        "INSERT INTO user_shortcuts (user_id, label, url, icon, color, sequence, is_custom, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"
    )
    .bind(user.id)
    .bind(&form.label)
    .bind(&form.url)
    .bind(form.icon.as_deref().unwrap_or("link"))
    .bind(form.color.as_deref().unwrap_or("primary"))
    .bind(next_seq)
    .bind(is_custom)
    .bind(company_id)
    .execute(&db)
    .await;

    // Return the updated shortcuts panel via HTMX
    home_shortcuts_partial(Db(db), Extension(user)).await.into_response()
}

async fn shortcut_remove(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let _ = sqlx::query(
        "UPDATE user_shortcuts SET active = false WHERE id = $1 AND user_id = $2"
    )
    .bind(id)
    .bind(user.id)
    .execute(&db)
    .await;

    home_shortcuts_partial(Db(db), Extension(user)).await.into_response()
}

async fn shortcuts_reorder(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<ShortcutReorderForm>,
) -> Response {
    let ids: Vec<&str> = form.ids.split(',').collect();
    for (i, id_str) in ids.iter().enumerate() {
        if let Ok(id) = uuid::Uuid::parse_str(id_str.trim()) {
            let _ = sqlx::query(
                "UPDATE user_shortcuts SET sequence = $1 WHERE id = $2 AND user_id = $3"
            )
            .bind((i as i32 + 1) * 10)
            .bind(id)
            .bind(user.id)
            .execute(&db)
            .await;
        }
    }

    home_shortcuts_partial(Db(db), Extension(user)).await.into_response()
}

// =============================================================================
// USER MANAGEMENT
// =============================================================================

#[derive(sqlx::FromRow)]
struct UserListRow {
    id: uuid::Uuid,
    username: String,
    email: String,
    full_name: Option<String>,
    active: bool,
    locked: bool,
    last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn users_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    // Only admins can access user management
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("User Management"))).into_response();
    }

    let users = sqlx::query_as::<_, UserListRow>(
        r#"
        SELECT id, username, email, full_name, active, locked, last_login_at, created_at
        FROM users
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let rows: String = users.iter().map(|u| {
        let status_badge = if u.locked {
            r#"<span class="badge badge-error badge-sm">Locked</span>"#
        } else if u.active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else {
            r#"<span class="badge badge-warning badge-sm">Disabled</span>"#
        };

        let last_login = u.last_login_at
            .map(|dt| format_time_ago(dt))
            .unwrap_or_else(|| "Never".to_string());

        let display_name = u.full_name.as_deref().unwrap_or("-");

        format!(
            r#"<tr>
                <td>
                    <div class="font-medium">{}</div>
                    <div class="text-sm text-base-content/60">{}</div>
                </td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>
                    <a href="/users/{}" class="btn btn-ghost btn-xs">Edit</a>
                </td>
            </tr>"#,
            u.username, u.email, display_name, status_badge, last_login, u.id
        )
    }).collect();

    let template = include_str!("../../templates/users_list.html");
    let html = template
        .replace("{{user_name}}", auth_user.full_name.as_deref().unwrap_or(&auth_user.username))
        .replace("{{user_initials}}", &get_initials(auth_user.full_name.as_deref().unwrap_or(&auth_user.username)))
        .replace("{{users_table_rows}}", &rows)
        .replace("{{user_count}}", &users.len().to_string());

    Html(html).into_response()
}

async fn users_new_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    // Only admins can create users
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Create User"))).into_response();
    }

    // Fetch available roles as a multi-select checkbox group
    let role_dropdown = generate_role_checkboxes(&db, &[]).await;

    let template = include_str!("../../templates/users_form.html");
    let html = template
        .replace("{{user_name}}", auth_user.full_name.as_deref().unwrap_or(&auth_user.username))
        .replace("{{user_initials}}", &get_initials(auth_user.full_name.as_deref().unwrap_or(&auth_user.username)))
        .replace("{{form_title}}", "Create User")
        .replace("{{form_action}}", "/users")
        .replace("{{username}}", "")
        .replace("{{email}}", "")
        .replace("{{full_name}}", "")
        .replace("{{username_readonly}}", "")
        .replace("{{password_section}}", r#"
            <div class="form-control">
                <label class="label"><span class="label-text">Password *</span></label>
                <input type="password" name="password" class="input input-bordered" required minlength="12"
                       placeholder="Minimum 12 characters">
                <label class="label"><span class="label-text-alt">Must include uppercase, lowercase, number, and special character</span></label>
            </div>
        "#)
        .replace("{{status_section}}", "")
        .replace("{{roles_checkboxes}}", &role_dropdown)
        .replace("{{submit_text}}", "Create User");

    Html(html).into_response()
}

/// Last-wins scalar lookup over urlencoded form pairs.
fn form_scalar<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Collect repeated checkbox values (e.g. `roles`) as UUIDs.
fn form_multi_uuids(pairs: &[(String, String)], key: &str) -> Vec<uuid::Uuid> {
    pairs
        .iter()
        .filter(|(k, _)| k == key)
        .filter_map(|(_, v)| v.parse::<uuid::Uuid>().ok())
        .collect()
}

async fn users_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    // Only admins can create users
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Create User"))).into_response();
    }

    let username = form_scalar(&pairs, "username").unwrap_or("").trim().to_string();
    let email = form_scalar(&pairs, "email").unwrap_or("").trim().to_string();
    let full_name = form_scalar(&pairs, "full_name").map(|s| s.to_string()).filter(|s| !s.is_empty());
    let password = form_scalar(&pairs, "password").unwrap_or("").to_string();
    let roles = form_multi_uuids(&pairs, "roles");

    if username.is_empty() || email.is_empty() {
        return error_response("Username and email are required");
    }
    // A user must have at least one role (otherwise they can do nothing).
    if roles.is_empty() {
        return error_response("Select at least one role");
    }

    // Validate password
    if password.len() < 12 {
        return error_response("Password must be at least 12 characters");
    }

    // Hash password
    let password_hash = hash_password(&password);

    // Get default company
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM companies LIMIT 1")
        .fetch_one(&db)
        .await
        .unwrap_or_else(|_| uuid::Uuid::nil());

    // Create user and get the new user's ID
    let new_user_id: Result<uuid::Uuid, _> = sqlx::query_scalar(
        r#"
        INSERT INTO users (company_id, username, email, password_hash, full_name, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        "#
    )
    .bind(&company_id)
    .bind(&username)
    .bind(&email)
    .bind(&password_hash)
    .bind(&full_name)
    .bind(&auth_user.id)
    .fetch_one(&db)
    .await;

    match new_user_id {
        Ok(user_id) => {
            // Assign every selected role.
            for role_id in &roles {
                let _ = sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING")
                    .bind(&user_id)
                    .bind(role_id)
                    .execute(&db)
                    .await;
            }

            // Log the action through the WORM ledger.
            let audit_entry = AuditEntry::new(AuditAction::UserCreated, AuditSeverity::Info)
                .with_user(vortex_common::UserId(auth_user.id))
                .with_username(&auth_user.username)
                .with_resource("user", user_id.to_string())
                .with_resource_name(&username)
                .with_details(serde_json::json!({
                    "new_username": username,
                    "role_ids": roles.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
                }));
            if let Err(e) = state.audit.log(audit_entry).await {
                error!("WORM audit write failed for UserCreated: {}", e);
            }

            // Redirect to users list (works for both HTMX and regular form)
            Redirect::to("/users").into_response()
        }
        Err(e) => {
            error!("Failed to create user: {}", e);
            if e.to_string().contains("duplicate") {
                error_response("Username or email already exists")
            } else {
                error_response("Failed to create user")
            }
        }
    }
}

async fn users_edit_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    // Only admins can edit users
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Edit User"))).into_response();
    }

    let user = sqlx::query_as::<_, UserListRow>(
        "SELECT id, username, email, full_name, active, locked, last_login_at, created_at FROM users WHERE id = $1"
    )
    .bind(&user_id)
    .fetch_optional(&db)
    .await;

    match user {
        Ok(Some(user)) => {
            // Get all of the user's current roles (a user may hold several).
            let current_roles: Vec<uuid::Uuid> = sqlx::query_scalar(
                "SELECT role_id FROM user_roles WHERE user_id = $1"
            )
            .bind(&user_id)
            .fetch_all(&db)
            .await
            .unwrap_or_default();

            // Generate the role checkbox group with current selections checked
            let role_dropdown = generate_role_checkboxes(&db, &current_roles).await;

            let status_section = format!(
                r#"
                <div class="divider">Status</div>
                <div class="flex gap-4">
                    <div class="form-control">
                        <label class="label cursor-pointer gap-2">
                            <input type="checkbox" name="active" class="checkbox checkbox-primary" {} />
                            <span class="label-text">Active</span>
                        </label>
                    </div>
                    {}
                </div>
                "#,
                if user.active { "checked" } else { "" },
                if user.locked {
                    format!(r#"<button type="button" hx-post="/users/{}/unlock" class="btn btn-warning btn-sm">Unlock Account</button>"#, user.id)
                } else {
                    String::new()
                }
            );

            let template = include_str!("../../templates/users_form.html");
            let html = template
                .replace("{{user_name}}", auth_user.full_name.as_deref().unwrap_or(&auth_user.username))
                .replace("{{user_initials}}", &get_initials(auth_user.full_name.as_deref().unwrap_or(&auth_user.username)))
                .replace("{{form_title}}", "Edit User")
                .replace("{{form_action}}", &format!("/users/{}", user.id))
                .replace("{{username}}", &user.username)
                .replace("{{email}}", &user.email)
                .replace("{{full_name}}", user.full_name.as_deref().unwrap_or(""))
                .replace("{{username_readonly}}", "readonly")
                .replace("{{password_section}}", r#"
                    <div class="form-control">
                        <label class="label"><span class="label-text">New Password</span></label>
                        <input type="password" name="password" class="input input-bordered" minlength="12"
                               placeholder="Leave blank to keep current">
                    </div>
                "#)
                .replace("{{status_section}}", &status_section)
                .replace("{{roles_checkboxes}}", &role_dropdown)
                .replace("{{submit_text}}", "Save Changes");

            Html(html).into_response()
        }
        Ok(None) => {
            (StatusCode::NOT_FOUND, Html("User not found")).into_response()
        }
        Err(e) => {
            error!("Database error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Html("Database error")).into_response()
        }
    }
}

async fn users_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<uuid::Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let email = form_scalar(&pairs, "email").unwrap_or("").trim().to_string();
    let full_name = form_scalar(&pairs, "full_name").map(|s| s.to_string()).filter(|s| !s.is_empty());
    let password = form_scalar(&pairs, "password").map(|s| s.to_string()).filter(|s| !s.is_empty());
    let active = form_scalar(&pairs, "active").is_some();
    let roles = form_multi_uuids(&pairs, "roles");
    // ─── Policy check (Phase 0.2) ──────────────────────────────────
    // Ask the Cedar policy engine instead of the hard-coded role check.
    // The seeded `admins_can_manage_users` policy grants update to
    // administrators; `self_service_profile_update` grants update to
    // anyone editing their own profile. Both match current behaviour,
    // so this is a semantic no-op but establishes the pattern every
    // future handler will use.
    let principal = PolicyPrincipal {
        user_id: auth_user.id,
        username: auth_user.username.clone(),
        // auth_user doesn't carry company_id today — fall back to the
        // system company. Tracked for Phase 0.2 follow-up: inject the
        // authenticated user's real tenant into AuthUser.
        company_id: uuid::Uuid::nil(),
        roles: auth_user
            .roles
            .iter()
            .map(|r| r.to_ascii_lowercase().replace(' ', "_"))
            .collect(),
    };
    let target_resource = PolicyResource {
        type_name: "User".into(),
        id: user_id.to_string(),
        attributes: serde_json::Value::Null,
    };
    match state.policy.check(&principal, "update", &target_resource).await {
        Ok(Decision::Allow { determining_policies }) => {
            tracing::debug!(
                determining = ?determining_policies,
                "users_update allowed by policy"
            );
        }
        Ok(Decision::Deny { determining_policies, reason }) => {
            warn!(
                actor = %auth_user.username,
                target = %user_id,
                reason = ?reason,
                determining = ?determining_policies,
                "users_update denied by policy"
            );
            // Record the denial in the WORM ledger.
            let audit_entry = AuditEntry::new(
                AuditAction::AccessDenied,
                AuditSeverity::Warning,
            )
            .with_user(vortex_common::UserId(auth_user.id))
            .with_username(&auth_user.username)
            .with_resource("user", user_id.to_string())
            .with_error("policy_denied")
            .with_details(serde_json::json!({
                "action": "update",
                "reason": format!("{:?}", reason),
                "determining_policies": determining_policies,
            }));
            if let Err(e) = state.audit.log(audit_entry).await {
                error!("WORM audit write failed for AccessDenied: {}", e);
            }
            return (StatusCode::FORBIDDEN, Html(forbidden_page("Update User"))).into_response();
        }
        Err(e) => {
            error!("Policy engine error during users_update: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("Authorization service unavailable"),
            )
                .into_response();
        }
    }

    let password_changed = password.is_some();

    // At least one role is required (don't silently strip a user's access).
    if roles.is_empty() {
        return error_response("Select at least one role");
    }

    // Update user
    let result = if let Some(password) = password {
        if password.len() < 12 {
            return error_response("Password must be at least 12 characters");
        }
        let password_hash = hash_password(&password);
        sqlx::query(
            r#"
            UPDATE users
            SET email = $1, full_name = $2, password_hash = $3, active = $4,
                password_changed_at = NOW(), updated_by = $5
            WHERE id = $6
            "#
        )
        .bind(&email)
        .bind(&full_name)
        .bind(&password_hash)
        .bind(active)
        .bind(&auth_user.id)
        .bind(&user_id)
        .execute(&db)
        .await
    } else {
        sqlx::query(
            r#"
            UPDATE users
            SET email = $1, full_name = $2, active = $3, updated_by = $4
            WHERE id = $5
            "#
        )
        .bind(&email)
        .bind(&full_name)
        .bind(active)
        .bind(&auth_user.id)
        .bind(&user_id)
        .execute(&db)
        .await
    };

    match result {
        Ok(_) => {
            // Replace the user's role set with the selected roles.
            let _ = sqlx::query("DELETE FROM user_roles WHERE user_id = $1")
                .bind(&user_id)
                .execute(&db)
                .await;

            for role_id in &roles {
                let _ = sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING")
                    .bind(&user_id)
                    .bind(role_id)
                    .execute(&db)
                    .await;
            }

            // Log the action through the WORM ledger.
            let audit_entry = AuditEntry::new(AuditAction::UserUpdated, AuditSeverity::Info)
                .with_user(vortex_common::UserId(auth_user.id))
                .with_username(&auth_user.username)
                .with_resource("user", user_id.to_string())
                .with_details(serde_json::json!({
                    "target_user_id": user_id.to_string(),
                    "new_email": email,
                    "active": active,
                    "role_ids": roles.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
                    "password_changed": password_changed,
                }));
            if let Err(e) = state.audit.log(audit_entry).await {
                error!("WORM audit write failed for UserUpdated: {}", e);
            }

            // Redirect to users list (works for both HTMX and regular form)
            Redirect::to("/users").into_response()
        }
        Err(e) => {
            error!("Failed to update user: {}", e);
            error_response("Failed to update user")
        }
    }
}

async fn users_toggle_active(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    // Only admins can toggle user status
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Toggle User Status"))).into_response();
    }

    let result = sqlx::query(
        "UPDATE users SET active = NOT active, updated_by = $1 WHERE id = $2"
    )
    .bind(&auth_user.id)
    .bind(&user_id)
    .execute(&db)
    .await;

    match result {
        Ok(_) => {
            let mut headers = HeaderMap::new();
            headers.insert("HX-Redirect", "/users".parse().unwrap());
            (StatusCode::OK, headers).into_response()
        }
        Err(e) => {
            error!("Failed to toggle user: {}", e);
            error_response("Failed to update user")
        }
    }
}

async fn users_unlock(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    // Only admins can unlock users
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Unlock User"))).into_response();
    }

    let result = sqlx::query(
        r#"
        UPDATE users
        SET locked = false, locked_at = NULL, locked_reason = NULL,
            failed_login_attempts = 0, updated_by = $1
        WHERE id = $2
        "#
    )
    .bind(&auth_user.id)
    .bind(&user_id)
    .execute(&db)
    .await;

    match result {
        Ok(_) => {
            // Log the action through the WORM ledger.
            let audit_entry = AuditEntry::new(AuditAction::UserUnlocked, AuditSeverity::Info)
                .with_user(vortex_common::UserId(auth_user.id))
                .with_username(&auth_user.username)
                .with_resource("user", user_id.to_string())
                .with_details(serde_json::json!({
                    "target_user_id": user_id.to_string(),
                }));
            if let Err(e) = state.audit.log(audit_entry).await {
                error!("WORM audit write failed for UserUnlocked: {}", e);
            }

            let mut headers = HeaderMap::new();
            headers.insert("HX-Redirect", format!("/users/{}", user_id).parse().unwrap());
            (StatusCode::OK, headers).into_response()
        }
        Err(e) => {
            error!("Failed to unlock user: {}", e);
            error_response("Failed to unlock user")
        }
    }
}

fn hash_password(password: &str) -> String {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

/// Seed core roles if they don't exist
pub async fn seed_core_roles_on_db(db: &PgPool) {
    seed_core_roles(db).await;
}

async fn seed_core_roles(db: &PgPool) {
    let roles = [
        ("System Administrator", "Full system access - all companies, audit logs, system settings"),
        ("Administrator", "Company administrator - manage users and data within company"),
        ("User", "Standard user - basic read access to allowed resources"),
    ];

    for (name, description) in roles {
        // Check if role exists
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1)")
            .bind(name)
            .fetch_one(db)
            .await
            .unwrap_or(false);

        if !exists {
            let result = sqlx::query(
                "INSERT INTO roles (name, description, is_system) VALUES ($1, $2, true)"
            )
            .bind(name)
            .bind(description)
            .execute(db)
            .await;

            match result {
                Ok(_) => info!("Created role: {}", name),
                Err(e) => warn!("Failed to create role {}: {}", name, e),
            }
        }
    }

    info!("Core roles verified");
}

#[derive(sqlx::FromRow)]
struct RoleRow {
    id: uuid::Uuid,
    name: String,
    description: Option<String>,
}

/// Generate HTML select dropdown for role selection
/// Render the role picker as a multi-select checkbox group. A user may hold
/// any number of roles (e.g. System Administrator *and* EAM Manager); the
/// `user_roles` table is many-to-many and the login path aggregates them all.
async fn generate_role_checkboxes(db: &PgPool, selected_roles: &[uuid::Uuid]) -> String {
    let roles = sqlx::query_as::<_, RoleRow>(
        "SELECT id, name, description FROM roles ORDER BY name"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    if roles.is_empty() {
        return r#"<p class="text-sm text-base-content/60">No roles available</p>"#.to_string();
    }

    let items: String = roles
        .iter()
        .map(|role| {
            let checked = if selected_roles.contains(&role.id) { "checked" } else { "" };
            let desc = role
                .description
                .as_deref()
                .filter(|d| !d.is_empty())
                .map(|d| format!(r#"<span class="label-text-alt opacity-60 ml-1">— {}</span>"#, html_escape(d)))
                .unwrap_or_default();
            format!(
                r#"<label class="label cursor-pointer justify-start gap-3 py-1">
                    <input type="checkbox" name="roles" value="{}" class="checkbox checkbox-primary checkbox-sm" {} />
                    <span class="label-text">{}</span>{}
                </label>"#,
                role.id,
                checked,
                html_escape(&role.name),
                desc
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<div class="flex flex-col gap-1 rounded-box border border-base-300 p-3 max-h-72 overflow-y-auto">
            {}
        </div>"#,
        items
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Access Control Page Handlers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct AccessPageQuery {
    #[serde(default = "default_tab")]
    tab: String,
}

fn default_tab() -> String {
    "models".to_string()
}

/// Main access control page
async fn access_control_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Query(query): axum::extract::Query<AccessPageQuery>,
) -> Response {
    // Only system administrators can access
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("<h1>Access Denied</h1><p>System Administrator access required.</p>")).into_response();
    }

    // Fetch model access rules
    let model_rules = sqlx::query_as::<_, ModelAccessRow>(
        r#"
        SELECT ma.id, ma.model_name, ma.role_id, r.name as role_name,
               ma.perm_read, ma.perm_write, ma.perm_create, ma.perm_delete, ma.active
        FROM model_access ma
        LEFT JOIN roles r ON r.id = ma.role_id
        ORDER BY ma.model_name, r.name
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Fetch record rules
    let record_rules = sqlx::query_as::<_, RecordRuleRow>(
        r#"
        SELECT rr.id, rr.name, rr.model_name, rr.domain_expression, rr.role_id,
               r.name as role_name, rr.perm_read, rr.perm_write, rr.perm_create,
               rr.perm_delete, rr.is_global, rr.priority, rr.active
        FROM record_rules rr
        LEFT JOIN roles r ON r.id = rr.role_id
        ORDER BY rr.model_name, rr.priority
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Fetch field access rules
    let field_rules = sqlx::query_as::<_, FieldAccessRow>(
        r#"
        SELECT fa.id, fa.model_name, fa.field_name, fa.role_id, r.name as role_name,
               fa.perm_read, fa.perm_write, fa.active
        FROM field_access fa
        LEFT JOIN roles r ON r.id = fa.role_id
        ORDER BY fa.model_name, fa.field_name, r.name
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let active_tab = query.tab;

    // Generate model rules HTML
    let model_rules_html: String = if model_rules.is_empty() {
        r#"<tr><td colspan="7" class="text-center py-8 text-base-content/60">No model access rules defined</td></tr>"#.to_string()
    } else {
        model_rules.iter().map(|rule| {
            format!(
                r#"<tr>
                    <td class="font-medium">{}</td>
                    <td>{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td>
                        <span class="badge badge-{}">{}</span>
                    </td>
                    <td>
                        <a href="/admin/access/models/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                    </td>
                </tr>"#,
                rule.model_name,
                rule.role_name.as_deref().unwrap_or("-"),
                if rule.perm_read { "✓" } else { "-" },
                if rule.perm_write { "✓" } else { "-" },
                if rule.perm_create { "✓" } else { "-" },
                if rule.perm_delete { "✓" } else { "-" },
                if rule.active { "success" } else { "ghost" },
                if rule.active { "Active" } else { "Inactive" },
                rule.id
            )
        }).collect()
    };

    // Generate record rules HTML
    let record_rules_html: String = if record_rules.is_empty() {
        r#"<tr><td colspan="9" class="text-center py-8 text-base-content/60">No record rules defined</td></tr>"#.to_string()
    } else {
        record_rules.iter().map(|rule| {
            format!(
                r#"<tr>
                    <td class="font-medium">{}</td>
                    <td>{}</td>
                    <td><code class="text-xs">{}</code></td>
                    <td>{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td>
                        <span class="badge badge-{}">{}</span>
                    </td>
                    <td>
                        <a href="/admin/access/rules/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                    </td>
                </tr>"#,
                rule.name,
                rule.model_name,
                rule.domain_expression,
                rule.role_name.as_deref().unwrap_or("Global"),
                if rule.perm_read { "✓" } else { "-" },
                if rule.perm_write { "✓" } else { "-" },
                if rule.perm_create { "✓" } else { "-" },
                if rule.perm_delete { "✓" } else { "-" },
                if rule.active { "success" } else { "ghost" },
                if rule.active { "Active" } else { "Inactive" },
                rule.id
            )
        }).collect()
    };

    // Generate field rules HTML
    let field_rules_html: String = if field_rules.is_empty() {
        r#"<tr><td colspan="6" class="text-center py-8 text-base-content/60">No field access rules defined</td></tr>"#.to_string()
    } else {
        field_rules.iter().map(|rule| {
            format!(
                r#"<tr>
                    <td class="font-medium">{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td>
                        <span class="badge badge-{}">{}</span>
                    </td>
                    <td>
                        <a href="/admin/access/fields/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                    </td>
                </tr>"#,
                rule.model_name,
                rule.field_name,
                rule.role_name.as_deref().unwrap_or("-"),
                if rule.perm_read { "✓" } else { "-" },
                if rule.perm_write { "✓" } else { "-" },
                if rule.active { "success" } else { "ghost" },
                if rule.active { "Active" } else { "Inactive" },
                rule.id
            )
        }).collect()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Control - Remicle</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
    <script src="/static/vendor/tailwind.js"></script>
    <script src="/static/vendor/htmx.min.js"></script>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
</head>
<body class="min-h-screen bg-base-200">
    <div class="drawer lg:drawer-open">
        <input id="drawer" type="checkbox" class="drawer-toggle" />
        <div class="drawer-content flex flex-col">
            <!-- Navbar -->
            <div class="navbar bg-base-100 shadow-sm">
                <div class="flex-none lg:hidden">
                    <label for="drawer" class="btn btn-square btn-ghost">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" class="inline-block w-6 h-6 stroke-current"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path></svg>
                    </label>
                </div>
                <div class="flex-1">
                    <span class="text-xl font-bold">Access Control</span>
                </div>
                <div class="flex-none">
                    <div class="dropdown dropdown-end">
                        <label tabindex="0" class="btn btn-ghost btn-circle avatar placeholder">
                            <div class="bg-primary text-primary-content rounded-full w-10">
                                <span>{}</span>
                            </div>
                        </label>
                        <ul tabindex="0" class="menu menu-sm dropdown-content mt-3 z-[1] p-2 shadow bg-base-100 rounded-box w-52">
                            <li><a>Profile</a></li>
                            <li>
                                <form method="post" action="/auth/logout">
                                    <button type="submit" class="w-full text-left">Logout</button>
                                </form>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <main class="flex-1 p-6">
                <div class="flex justify-between items-center mb-6">
                    <h1 class="text-2xl font-bold">Access Control Management</h1>
                </div>

                <!-- Tabs -->
                <div role="tablist" class="tabs tabs-boxed mb-6">
                    <a role="tab" href="/admin/access?tab=models" class="tab {}"">Model Access</a>
                    <a role="tab" href="/admin/access?tab=rules" class="tab {}">Record Rules</a>
                    <a role="tab" href="/admin/access?tab=fields" class="tab {}">Field Access</a>
                </div>

                <!-- Model Access Tab -->
                <div class="{}" id="models-tab">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-lg font-semibold">Model Access Rules</h2>
                        <a href="/admin/access/models/new" class="btn btn-primary btn-sm">+ Add Rule</a>
                    </div>
                    <div class="overflow-x-auto bg-base-100 rounded-lg shadow">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Model</th>
                                    <th>Role</th>
                                    <th class="text-center">Read</th>
                                    <th class="text-center">Write</th>
                                    <th class="text-center">Create</th>
                                    <th class="text-center">Delete</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Record Rules Tab -->
                <div class="{}" id="rules-tab">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-lg font-semibold">Record Rules</h2>
                        <a href="/admin/access/rules/new" class="btn btn-primary btn-sm">+ Add Rule</a>
                    </div>
                    <div class="overflow-x-auto bg-base-100 rounded-lg shadow">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Model</th>
                                    <th>Domain</th>
                                    <th>Role</th>
                                    <th class="text-center">Read</th>
                                    <th class="text-center">Write</th>
                                    <th class="text-center">Create</th>
                                    <th class="text-center">Delete</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Field Access Tab -->
                <div class="{}" id="fields-tab">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-lg font-semibold">Field Access Rules</h2>
                        <a href="/admin/access/fields/new" class="btn btn-primary btn-sm">+ Add Rule</a>
                    </div>
                    <div class="overflow-x-auto bg-base-100 rounded-lg shadow">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Model</th>
                                    <th>Field</th>
                                    <th>Role</th>
                                    <th class="text-center">Read</th>
                                    <th class="text-center">Write</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {}
                            </tbody>
                        </table>
                    </div>
                </div>
            </main>
        </div>

        <!-- Sidebar -->
        <div class="drawer-side">
            <label for="drawer" aria-label="close sidebar" class="drawer-overlay"></label>
            <aside class="bg-base-100 w-64 min-h-screen">
                <div class="p-4 border-b">
                    <h1 class="text-xl font-bold"><span class="text-primary">re</span><span class="text-base-content/60">micle</span></h1>
                </div>
                <ul class="menu p-4">
                    <li class="menu-title">
                        <span>Main</span>
                    </li>
                    <li>
                        <a href="/home">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path></svg>
                            Home
                        </a>
                    </li>
                    <li class="menu-title mt-4">
                        <span>Administration</span>
                    </li>
                    <li>
                        <a href="/users">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
                            Users
                        </a>
                    </li>
                    <li>
                        <a href="/admin/access" class="active">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                            Access Control
                        </a>
                    </li>
                </ul>
            </aside>
        </div>
    </div>
</body>
</html>"#,
        get_initials(&user.full_name.as_deref().unwrap_or(&user.username)),
        if active_tab == "models" { "tab-active" } else { "" },
        if active_tab == "rules" { "tab-active" } else { "" },
        if active_tab == "fields" { "tab-active" } else { "" },
        if active_tab == "models" { "" } else { "hidden" },
        model_rules_html,
        if active_tab == "rules" { "" } else { "hidden" },
        record_rules_html,
        if active_tab == "fields" { "" } else { "hidden" },
        field_rules_html
    );

    Html(html).into_response()
}

#[derive(sqlx::FromRow)]
struct ModelAccessRow {
    id: uuid::Uuid,
    model_name: String,
    role_id: uuid::Uuid,
    role_name: Option<String>,
    perm_read: bool,
    perm_write: bool,
    perm_create: bool,
    perm_delete: bool,
    active: bool,
}

#[derive(sqlx::FromRow)]
struct RecordRuleRow {
    id: uuid::Uuid,
    name: String,
    model_name: String,
    domain_expression: String,
    role_id: Option<uuid::Uuid>,
    role_name: Option<String>,
    perm_read: bool,
    perm_write: bool,
    perm_create: bool,
    perm_delete: bool,
    is_global: bool,
    priority: i32,
    active: bool,
}

#[derive(sqlx::FromRow)]
struct FieldAccessRow {
    id: uuid::Uuid,
    model_name: String,
    field_name: String,
    role_id: uuid::Uuid,
    role_name: Option<String>,
    perm_read: bool,
    perm_write: bool,
    active: bool,
}

// Placeholder handlers for edit/create pages
async fn access_model_new_page(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>New Model Access Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_model_create(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=models").into_response()
}

async fn access_model_edit_page(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>Edit Model Access Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_model_update(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=models").into_response()
}

async fn access_rule_new_page(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>New Record Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_rule_create(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=rules").into_response()
}

async fn access_rule_edit_page(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>Edit Record Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_rule_update(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=rules").into_response()
}

async fn access_field_new_page(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>New Field Access Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_field_create(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=fields").into_response()
}

async fn access_field_edit_page(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>Edit Field Access Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_field_update(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=fields").into_response()
}

// ============================================================================
// Module Management Handlers
// ============================================================================

async fn modules_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    modules_list_with_filter(State(state), Db(db), Extension(user), Path("all".to_string())).await
}

async fn modules_list_with_filter(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(filter): Path<String>,
) -> Response {
    // Fetch all modules from database
    let modules = sqlx::query(
        r#"
        SELECT
            im.id, im.technical_name, im.name, im.version, im.state,
            COALESCE(im.category, 'Uncategorized') as category,
            COALESCE(im.summary, '') as summary,
            im.is_core, im.application, im.installed_at
        FROM installed_modules im
        ORDER BY im.sequence, im.name
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let installed_count = modules.iter().filter(|m| {
        let state: String = m.get("state");
        state == "installed"
    }).count();
    let available_count = modules.iter().filter(|m| {
        let state: String = m.get("state");
        state != "installed"
    }).count();

    // Build modules HTML
    let mut modules_html = String::new();
    for module in &modules {
        let tech_name: String = module.get("technical_name");
        let name: String = module.get("name");
        let version: String = module.get("version");
        let state_val: String = module.get("state");
        let category: String = module.get("category");
        let summary: String = module.get("summary");
        let is_core: bool = module.get("is_core");
        let application: bool = module.get("application");
        let installed_at: Option<chrono::DateTime<chrono::Utc>> = module.get("installed_at");

        // Apply filter
        if filter == "installed" && state_val != "installed" {
            continue;
        }
        if filter == "available" && state_val == "installed" {
            continue;
        }

        let initial = name.chars().next().unwrap_or('M');
        let gradient_class = if is_core {
            "from-purple-500 to-purple-700"
        } else if application {
            "from-blue-500 to-blue-700"
        } else {
            "from-gray-400 to-gray-600"
        };

        let type_badge = if is_core {
            r#"<span class="badge badge-xs badge-primary">Core</span>"#
        } else if application {
            r#"<span class="badge badge-xs badge-info">App</span>"#
        } else {
            ""
        };

        let status_badge = match state_val.as_str() {
            "installed" => r#"<span class="badge badge-success gap-1"><svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>Installed</span>"#,
            "to_install" => r#"<span class="badge badge-warning">Installing...</span>"#,
            "to_upgrade" => r#"<span class="badge badge-warning">Upgrading...</span>"#,
            "to_remove" => r#"<span class="badge badge-error">Removing...</span>"#,
            _ => r#"<span class="badge badge-ghost">Not Installed</span>"#,
        };

        let installed_text = installed_at
            .map(|dt| format!(r#"<span class="text-xs text-base-content/50">Installed: {}</span>"#, dt.format("%Y-%m-%d %H:%M")))
            .unwrap_or_else(|| "<span></span>".to_string());

        let action_buttons = if state_val == "installed" {
            let uninstall_btn = if !is_core {
                format!(r#"<button class="btn btn-sm btn-ghost text-error" onclick="uninstallModule('{}', '{}')"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>Uninstall</button>"#, tech_name, name)
            } else {
                String::new()
            };
            format!(r#"{}<button class="btn btn-sm btn-ghost" onclick="upgradeModule('{}', '{}')"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>Upgrade</button>"#, uninstall_btn, tech_name, name)
        } else {
            format!(r#"<button class="btn btn-sm btn-primary" onclick="installModule('{}', '{}')"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>Install</button>"#, tech_name, name)
        };
        // Prepend a "Details" link to each card's actions.
        let action_buttons = format!(
            r#"<a href="/modules/app/{}" class="btn btn-sm btn-ghost">Details</a>{}"#,
            tech_name, action_buttons
        );

        modules_html.push_str(&format!(r#"
        <div class="card bg-base-100 shadow-md hover:shadow-lg transition-shadow" id="module-{}">
            <div class="card-body p-4">
                <div class="flex items-start gap-3">
                    <div class="w-12 h-12 rounded-lg bg-gradient-to-br {} flex items-center justify-center text-white text-xl font-bold shrink-0">{}</div>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2">
                            <h3 class="font-semibold text-lg truncate">{}</h3>
                            {}
                        </div>
                        <div class="flex items-center gap-2 text-sm text-base-content/60">
                            <span>v{}</span>
                            <span class="text-base-content/40">|</span>
                            <span>{}</span>
                        </div>
                    </div>
                    <div>{}</div>
                </div>
                {}
                <div class="card-actions justify-between items-center mt-4 pt-3 border-t border-base-200">
                    {}
                    <div class="flex gap-2">{}</div>
                </div>
            </div>
        </div>
        "#,
            tech_name, gradient_class, initial, name, type_badge, version, category, status_badge,
            if !summary.is_empty() { format!(r#"<p class="text-sm text-base-content/70 mt-2 line-clamp-2">{}</p>"#, summary) } else { String::new() },
            installed_text, action_buttons
        ));
    }

    if modules_html.is_empty() {
        modules_html = r#"
        <div class="col-span-full">
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-base-content/30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/>
                </svg>
                <h3 class="mt-4 text-lg font-medium text-base-content/70">No modules found</h3>
            </div>
        </div>
        "#.to_string();
    }

    let filter_tabs = format!(r#"
    <div class="tabs tabs-boxed bg-base-200 w-fit mb-6">
        <a href="/modules/all" class="tab{}"">All</a>
        <a href="/modules/installed" class="tab{}">Installed</a>
        <a href="/modules/available" class="tab{}">Available</a>
    </div>
    "#,
        if filter == "all" { " tab-active" } else { "" },
        if filter == "installed" { " tab-active" } else { "" },
        if filter == "available" { " tab-active" } else { "" }
    );

    let html = format!(r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Apps & Modules - Remicle</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet" type="text/css" />
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
    <script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar-modules').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay-modules').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="text-base-content/60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
    <div id="sidebar-overlay-modules" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar-modules').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
    <div class="flex">
        <!-- Sidebar -->
        <aside id="sidebar-modules" class="w-64 bg-base-100 shadow-lg flex flex-col min-h-screen fixed lg:static top-0 left-0 z-40 h-full -translate-x-full lg:translate-x-0 transition-transform duration-200">
            <div class="p-4 border-b border-base-300">
                <a href="/home" class="flex justify-center">
                    <span class="text-xl font-bold"><span class="text-success">re</span><span class="text-base-content/60">micle</span></span>
                </a>
            </div>
            <nav class="flex-1 overflow-y-auto p-4">
                <ul class="menu menu-sm gap-1">
                    <li><a href="/home">Home</a></li>
                    <li class="menu-title mt-4"><span>Administration</span></li>
                    <li><a href="/users">Users</a></li>
                    <li><a href="/admin/access">Access Control</a></li>
                    <li class="menu-title mt-4"><span>Apps</span></li>
                    <li><a href="/modules" class="active">Apps & Modules</a></li>
                </ul>
            </nav>
        </aside>

        <!-- Main Content -->
        <main class="flex-1 p-4 lg:p-6 min-w-0">
            <div class="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
                <div>
                    <h1 class="text-2xl font-bold">Apps & Modules</h1>
                    <p class="text-base-content/60 mt-1">Install and manage application modules</p>
                </div>
                <div class="mt-4 md:mt-0 flex items-center gap-3">
                    <button onclick="refreshApps()" class="btn btn-outline btn-sm gap-2" title="Scan compiled-in plugins and add any new apps to this database's list">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                        Update Apps List
                    </button>
                    <div class="stats shadow bg-base-100">
                        <div class="stat py-2 px-4">
                            <div class="stat-title text-xs">Installed</div>
                            <div class="stat-value text-lg text-success">{}</div>
                        </div>
                        <div class="stat py-2 px-4">
                            <div class="stat-title text-xs">Available</div>
                            <div class="stat-value text-lg text-base-content/60">{}</div>
                        </div>
                    </div>
                </div>
            </div>

            {}

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {}
            </div>
        </main>
    </div>

    <!-- Loading Modal -->
    <dialog id="loading-modal" class="modal">
        <div class="modal-box w-80">
            <div class="flex items-center gap-4">
                <span class="loading loading-spinner loading-lg text-primary"></span>
                <div>
                    <h3 class="font-bold" id="loading-title">Processing...</h3>
                    <p class="text-sm text-base-content/60" id="loading-message">Please wait...</p>
                </div>
            </div>
        </div>
    </dialog>

    <!-- Result Modal -->
    <dialog id="result-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg" id="result-title">Result</h3>
            <p class="py-4" id="result-message"></p>
            <div class="modal-action">
                <button class="btn" onclick="document.getElementById('result-modal').close()">Close</button>
            </div>
        </div>
    </dialog>

    <script>
    async function refreshApps() {{
        showLoading('Updating Apps List', 'Scanning available modules...');
        try {{
            const response = await fetch('/modules/refresh', {{ method: 'POST' }});
            const data = await response.json();
            hideLoading();
            if (data.success) {{
                showResult('Apps List Updated', data.message, 'success');
                setTimeout(() => location.reload(), 1500);
            }} else {{
                showResult('Error', data.error || data.message, 'error');
            }}
        }} catch (error) {{
            hideLoading();
            showResult('Error', 'Failed to update apps list: ' + error.message, 'error');
        }}
    }}

    async function installModule(technicalName, displayName) {{
        showLoading('Installing Module', `Installing ${{displayName}}...`);
        try {{
            const response = await fetch(`/modules/${{technicalName}}/install`, {{ method: 'POST' }});
            const data = await response.json();
            hideLoading();
            if (data.success) {{
                showResult('Success', data.message, 'success');
                setTimeout(() => location.reload(), 1500);
            }} else {{
                showResult('Error', data.error || data.message, 'error');
            }}
        }} catch (error) {{
            hideLoading();
            showResult('Error', 'Failed to install module: ' + error.message, 'error');
        }}
    }}

    async function uninstallModule(technicalName, displayName) {{
        if (!confirm(`Are you sure you want to uninstall "${{displayName}}"?`)) return;
        showLoading('Uninstalling Module', `Uninstalling ${{displayName}}...`);
        try {{
            const response = await fetch(`/modules/${{technicalName}}/uninstall`, {{ method: 'POST' }});
            const data = await response.json();
            hideLoading();
            if (data.success) {{
                showResult('Success', data.message, 'success');
                setTimeout(() => location.reload(), 1500);
            }} else {{
                showResult('Error', data.error || data.message, 'error');
            }}
        }} catch (error) {{
            hideLoading();
            showResult('Error', 'Failed to uninstall module: ' + error.message, 'error');
        }}
    }}

    async function upgradeModule(technicalName, displayName) {{
        showLoading('Upgrading Module', `Upgrading ${{displayName}}...`);
        try {{
            const response = await fetch(`/modules/${{technicalName}}/upgrade`, {{ method: 'POST' }});
            const data = await response.json();
            hideLoading();
            if (data.success) {{
                showResult('Success', data.message, 'success');
                setTimeout(() => location.reload(), 1500);
            }} else {{
                showResult('Error', data.error || data.message, 'error');
            }}
        }} catch (error) {{
            hideLoading();
            showResult('Error', 'Failed to upgrade module: ' + error.message, 'error');
        }}
    }}

    function showLoading(title, message) {{
        document.getElementById('loading-title').textContent = title;
        document.getElementById('loading-message').textContent = message;
        document.getElementById('loading-modal').showModal();
    }}
    function hideLoading() {{ document.getElementById('loading-modal').close(); }}
    function showResult(title, message, type) {{
        document.getElementById('result-title').textContent = title;
        document.getElementById('result-title').className = 'font-bold text-lg ' + (type === 'success' ? 'text-success' : 'text-error');
        document.getElementById('result-message').textContent = message;
        document.getElementById('result-modal').showModal();
    }}
    </script>
</body>
</html>"#, installed_count, available_count, filter_tabs, modules_html);

    Html(html).into_response()
}

#[derive(serde::Serialize)]
struct ModuleOperationResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Per-app detail page: rich, author-declared metadata (description,
/// author, category, website), the dependency graph (with each related
/// module's install state), what the app provides (migrations, menu
/// entries), and install/uninstall actions. Metadata is read live from
/// the plugin registry (source of truth); install state from this
/// tenant's `installed_modules`.
async fn modules_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Response {
    let row = sqlx::query(
        "SELECT name, version, state, COALESCE(category,'Uncategorized') AS category, \
         COALESCE(summary,'') AS summary, is_core, application, installed_at \
         FROM installed_modules WHERE technical_name = $1",
    )
    .bind(&id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let plugin = state
        .plugin_registry
        .plugins_iter()
        .find(|p| p.technical_name() == id.as_str())
        .cloned();

    if row.is_none() && plugin.is_none() {
        return (StatusCode::NOT_FOUND, "App not found").into_response();
    }

    // Resolve fields, preferring the live registry over the stored row.
    let name = plugin
        .as_ref()
        .map(|p| p.display_name().to_string())
        .or_else(|| row.as_ref().map(|r| r.get::<String, _>("name")))
        .unwrap_or_else(|| id.clone());
    let version = plugin
        .as_ref()
        .map(|p| p.version().to_string())
        .or_else(|| row.as_ref().map(|r| r.get::<String, _>("version")))
        .unwrap_or_default();
    let state_val = row
        .as_ref()
        .map(|r| r.get::<String, _>("state"))
        .unwrap_or_else(|| "uninstalled".to_string());
    let is_core = row.as_ref().map(|r| r.get::<bool, _>("is_core")).unwrap_or(false);
    let category = plugin
        .as_ref()
        .map(|p| p.category().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| row.as_ref().map(|r| r.get::<String, _>("category")))
        .unwrap_or_else(|| "Uncategorized".into());
    let author = plugin.as_ref().map(|p| p.author().to_string()).unwrap_or_default();
    let website = plugin.as_ref().map(|p| p.website().to_string()).unwrap_or_default();
    let description = plugin.as_ref().map(|p| p.description().to_string()).unwrap_or_default();

    let deps: Vec<String> = plugin
        .as_ref()
        .map(|p| p.dependencies().iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();
    let migrations: Vec<String> = plugin
        .as_ref()
        .map(|p| p.migrations().iter().map(|m| m.name.to_string()).collect())
        .unwrap_or_default();
    let menus: Vec<String> = plugin
        .as_ref()
        .map(|p| p.menu_entries().iter().map(|m| m.label.clone()).collect())
        .unwrap_or_default();

    let mut dependents: Vec<String> = state
        .plugin_registry
        .plugins_iter()
        .filter(|p| p.dependencies().iter().any(|d| *d == id.as_str()))
        .map(|p| p.technical_name().to_string())
        .collect();
    dependents.sort();

    // Dependencies list with each related module's install state.
    let mut deps_html = String::new();
    if deps.is_empty() {
        deps_html.push_str(r#"<li class="text-base-content/50">None</li>"#);
    } else {
        for d in &deps {
            let st: Option<String> =
                sqlx::query_scalar("SELECT state FROM installed_modules WHERE technical_name = $1")
                    .bind(d)
                    .fetch_optional(&db)
                    .await
                    .ok()
                    .flatten();
            let badge = match st.as_deref() {
                Some("installed") => r#"<span class="badge badge-success badge-sm">installed</span>"#,
                None => r#"<span class="badge badge-error badge-sm">not in this database</span>"#,
                _ => r#"<span class="badge badge-ghost badge-sm">available</span>"#,
            };
            deps_html.push_str(&format!(
                r#"<li class="flex items-center gap-2"><a href="/modules/app/{0}" class="link link-hover font-medium">{1}</a>{2}</li>"#,
                html_escape(d), html_escape(d), badge
            ));
        }
    }

    // "Required by" (dependents).
    let dependents_html = if dependents.is_empty() {
        r#"<li class="text-base-content/50">Nothing depends on this app</li>"#.to_string()
    } else {
        dependents
            .iter()
            .map(|t| format!(r#"<li><a href="/modules/app/{0}" class="link link-hover">{1}</a></li>"#, html_escape(t), html_escape(t)))
            .collect::<String>()
    };

    let list_or_none = |items: &[String]| -> String {
        if items.is_empty() {
            r#"<li class="text-base-content/50">None</li>"#.to_string()
        } else {
            items.iter().map(|i| format!("<li>{}</li>", html_escape(i))).collect()
        }
    };
    let migrations_html = list_or_none(&migrations);
    let menus_html = list_or_none(&menus);

    let status_badge = match state_val.as_str() {
        "installed" => r#"<span class="badge badge-success">Installed</span>"#,
        _ => r#"<span class="badge badge-ghost">Not installed</span>"#,
    };
    let action_btn = if is_core {
        r#"<span class="text-sm text-base-content/50">Core module — always on</span>"#.to_string()
    } else if state_val == "installed" {
        r#"<button class="btn btn-error btn-outline btn-sm" onclick="act('uninstall')">Uninstall</button>"#.to_string()
    } else {
        r#"<button class="btn btn-primary btn-sm" onclick="act('install')">Install</button>"#.to_string()
    };
    let dep_note = if deps.is_empty() {
        String::new()
    } else {
        format!(
            r#"<p class="text-xs text-base-content/50 mt-2">Installing this app also installs: {}</p>"#,
            html_escape(&deps.join(", "))
        )
    };
    let website_html = if website.is_empty() {
        String::new()
    } else {
        format!(r#"<a href="{0}" class="link link-primary" target="_blank" rel="noopener">{0}</a>"#, html_escape(&website))
    };
    let desc_html = if description.is_empty() {
        r#"<p class="text-base-content/50">No description provided.</p>"#.to_string()
    } else {
        format!(r#"<p class="leading-relaxed">{}</p>"#, html_escape(&description))
    };

    let mut page = format!(
        r#"<!DOCTYPE html><html lang="en" data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{name} - Apps & Modules</title>
<link href="/static/vendor/daisyui.min.css" rel="stylesheet" type="text/css"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200"><main class="max-w-4xl mx-auto p-4 lg:p-8">
<a href="/modules" class="btn btn-ghost btn-sm mb-4 gap-2">← Back to Apps &amp; Modules</a>
<div class="card bg-base-100 shadow-md mb-4"><div class="card-body">
<div class="flex items-start justify-between gap-4">
<div>
<div class="flex items-center gap-3"><h1 class="text-3xl font-bold">{name}</h1>{status_badge}</div>
<div class="flex flex-wrap items-center gap-2 text-sm text-base-content/60 mt-2">
<span class="badge badge-outline">{category}</span><span>v{version}</span>
<span class="text-base-content/30">|</span><span>{tech}</span></div>
</div>
<div class="flex flex-col items-end gap-1">{action_btn}{dep_note}</div>
</div>
<div class="divider my-2"></div>
{desc_html}
<div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4 text-sm">
<div><span class="text-base-content/50">Author:</span> {author}</div>
<div><span class="text-base-content/50">Website:</span> {website_html}</div>
</div>
</div></div>
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div class="card bg-base-100 shadow-md"><div class="card-body">
<h2 class="card-title text-lg">Dependencies</h2>
<ul class="menu menu-sm px-0">{deps_html}</ul>
<h3 class="font-semibold mt-3">Required by</h3>
<ul class="menu menu-sm px-0">{dependents_html}</ul>
</div></div>
<div class="card bg-base-100 shadow-md"><div class="card-body">
<h2 class="card-title text-lg">Provides</h2>
<h3 class="font-semibold">Menu entries</h3><ul class="list-disc pl-5">{menus_html}</ul>
<h3 class="font-semibold mt-3">Migrations</h3><ul class="list-disc pl-5 font-mono text-xs">{migrations_html}</ul>
</div></div>
</div>
</main>"#,
        name = html_escape(&name),
        status_badge = status_badge,
        category = html_escape(&category),
        version = html_escape(&version),
        tech = html_escape(&id),
        action_btn = action_btn,
        dep_note = dep_note,
        desc_html = desc_html,
        author = if author.is_empty() { "<span class=\"text-base-content/50\">—</span>".to_string() } else { html_escape(&author) },
        website_html = if website_html.is_empty() { "<span class=\"text-base-content/50\">—</span>".to_string() } else { website_html },
        deps_html = deps_html,
        dependents_html = dependents_html,
        menus_html = menus_html,
        migrations_html = migrations_html,
    );

    // Action script (raw block: literal braces, no format escaping).
    page.push_str(&format!(r#"<script>const APP_ID={:?};</script>"#, id));
    page.push_str(r#"<script>
async function act(kind){
  try{
    const r = await fetch('/modules/'+APP_ID+'/'+kind, {method:'POST'});
    const d = await r.json();
    if(d.success){ location.href='/modules'; }
    else { alert(d.error || d.message || 'Action failed'); }
  }catch(e){ alert('Request failed: '+e.message); }
}
</script></body></html>"#);

    axum::response::Html(page).into_response()
}

/// Dependency-first install order for `target`, from each plugin's
/// declared `dependencies()`. A dependency always appears before the
/// module that needs it; `target` is last. Cycles are broken via `seen`.
fn resolve_install_order(registry: &PluginRegistry, target: &str) -> Vec<String> {
    fn visit(
        registry: &PluginRegistry,
        name: &str,
        ordered: &mut Vec<String>,
        seen: &mut std::collections::HashSet<String>,
    ) {
        if !seen.insert(name.to_string()) {
            return;
        }
        if let Some(p) = registry.plugins_iter().find(|p| p.technical_name() == name) {
            for dep in p.dependencies() {
                visit(registry, dep, ordered, seen);
            }
        }
        ordered.push(name.to_string());
    }
    let mut ordered = Vec::new();
    let mut seen = std::collections::HashSet::new();
    visit(registry, target, &mut ordered, &mut seen);
    ordered
}

/// "Update Apps List" — scan the compiled-in plugin registry and upsert
/// each plugin into THIS tenant database's `installed_modules` table, so
/// newly built/shipped modules become visible (and installable) without
/// a server restart. Mirrors Odoo's "Update Apps List". Admin-only.
///
/// Background: the startup sync (`sync_plugins_best_effort`) only runs
/// against the primary DB, so tenant DBs never see new apps until this
/// runs against them.
async fn modules_refresh(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    if !user.is_system_admin() {
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Permission denied".to_string(),
            error: Some("Only system administrators can update the apps list".to_string()),
        }).into_response();
    }

    // Project plugin `#[derive(Model)]` metadata into this tenant's registry
    // (ir_model / ir_model_field) so refreshing the apps list also refreshes
    // the generic-view + REST-API metadata. Mirrors the CLI `db migrate` path.
    {
        let metas: Vec<&'static vortex_orm::model::ModelMeta> = state
            .plugin_registry
            .plugins_iter()
            .flat_map(|p| p.models())
            .collect();
        if !metas.is_empty() {
            if let Err(e) = vortex_orm::registry_sync::sync_model_registry(&db, &metas).await {
                error!("model registry sync during apps-list refresh failed: {}", e);
            }
        }
    }

    match crate::commands::module_sync::sync_plugins_to_installed_modules(&db, &state.plugin_registry).await {
        Ok((inserted, updated)) => {
            let audit = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
                .with_user(vortex_common::UserId(user.id))
                .with_username(&user.username)
                .with_database(&db_ctx.db_name)
                .with_resource("modules", "apps_list".to_string())
                .with_details(serde_json::json!({ "inserted": inserted, "updated": updated }));
            if let Err(e) = state.audit.log(audit).await {
                error!("audit log for apps-list update failed: {}", e);
            }
            axum::Json(ModuleOperationResponse {
            success: true,
            message: format!(
                "Apps list updated — {} new app(s) added, {} refreshed. New apps appear under \"Available\".",
                inserted, updated
            ),
            error: None,
        })
        .into_response()
        }
        Err(e) => axum::Json(ModuleOperationResponse {
            success: false,
            message: "Failed to update apps list".to_string(),
            error: Some(e.to_string()),
        })
        .into_response(),
    }
}

async fn module_install(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(module_id): Path<String>,
) -> Response {
    if !user.is_system_admin() {
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Permission denied".to_string(),
            error: Some("Only system administrators can install modules".to_string()),
        }).into_response();
    }

    // Check if module exists
    let module = sqlx::query(
        "SELECT technical_name, name, state FROM installed_modules WHERE technical_name = $1"
    )
    .bind(&module_id)
    .fetch_optional(&db)
    .await;

    let module = match module {
        Ok(Some(m)) => m,
        Ok(None) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Module not found".to_string(),
                error: Some(format!("Module '{}' not found", module_id)),
            }).into_response();
        }
        Err(e) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Database error".to_string(),
                error: Some(e.to_string()),
            }).into_response();
        }
    };

    let name: String = module.get("name");
    let current_state: String = module.get("state");

    if current_state == "installed" {
        return axum::Json(ModuleOperationResponse {
            success: true,
            message: format!("Module '{}' is already installed", name),
            error: None,
        }).into_response();
    }

    // Install dependency-first: a plugin's declared dependencies are
    // provisioned and activated before the plugin itself (e.g. installing
    // "purchase" auto-pulls "inventory"). Each step provisions the
    // module's schema in THIS tenant DB, then flips state — previously the
    // UI only flipped the flag, leaving tenant tables uncreated.
    let order = resolve_install_order(&state.plugin_registry, &module_id);
    let mut also_installed: Vec<String> = Vec::new();
    for tech in &order {
        let st: Option<String> =
            sqlx::query_scalar("SELECT state FROM installed_modules WHERE technical_name = $1")
                .bind(tech)
                .fetch_optional(&db)
                .await
                .ok()
                .flatten();
        if st.as_deref() == Some("installed") {
            continue;
        }

        // Provision schema (no-op for core modules / no migrations).
        if let Err(e) = crate::commands::db::install_plugin_schema(&db, tech).await {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Installation failed".to_string(),
                error: Some(format!("Could not apply '{}' schema to this database: {}", tech, e)),
            }).into_response();
        }

        if let Err(e) = sqlx::query(
            "UPDATE installed_modules SET state = 'installed', installed_at = NOW(), updated_at = NOW() WHERE technical_name = $1"
        )
        .bind(tech)
        .execute(&db)
        .await
        {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Installation failed".to_string(),
                error: Some(e.to_string()),
            }).into_response();
        }

        if tech != &module_id {
            also_installed.push(tech.clone());
        }
    }

    // Refresh installed modules cache.
    let new_installed: Vec<String> = sqlx::query_scalar(
        "SELECT technical_name FROM installed_modules WHERE state = 'installed'"
    ).fetch_all(&db).await.unwrap_or_default();
    {
        let mut cache = state.installed_modules.write().await;
        *cache = new_installed.into_iter().collect();
    }

    // Audit the install (state-changing admin action). Routed to the
    // tenant DB so it shows in that tenant's Recent Activity / ledger.
    let audit = AuditEntry::new(AuditAction::ModuleLoaded, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("module", module_id.clone())
        .with_resource_name(&name)
        .with_details(serde_json::json!({ "dependencies_installed": also_installed }));
    if let Err(e) = state.audit.log(audit).await {
        error!("audit log for module install failed: {}", e);
    }

    let message = if also_installed.is_empty() {
        format!("Module '{}' installed successfully", name)
    } else {
        format!(
            "Module '{}' installed, along with its dependencies: {}",
            name,
            also_installed.join(", ")
        )
    };
    axum::Json(ModuleOperationResponse { success: true, message, error: None }).into_response()
}

async fn module_uninstall(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(module_id): Path<String>,
) -> Response {
    if !user.is_system_admin() {
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Permission denied".to_string(),
            error: Some("Only system administrators can uninstall modules".to_string()),
        }).into_response();
    }

    // Check if module exists
    let module = sqlx::query(
        "SELECT technical_name, name, state, is_core FROM installed_modules WHERE technical_name = $1"
    )
    .bind(&module_id)
    .fetch_optional(&db)
    .await;

    let module = match module {
        Ok(Some(m)) => m,
        Ok(None) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Module not found".to_string(),
                error: Some(format!("Module '{}' not found", module_id)),
            }).into_response();
        }
        Err(e) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Database error".to_string(),
                error: Some(e.to_string()),
            }).into_response();
        }
    };

    let name: String = module.get("name");
    let is_core: bool = module.get("is_core");

    if is_core {
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Cannot uninstall core module".to_string(),
            error: Some(format!("Module '{}' is a core module and cannot be uninstalled", name)),
        }).into_response();
    }

    // Check for dependent modules
    let dependents = sqlx::query(
        r#"
        SELECT im.name
        FROM installed_modules im
        JOIN module_dependencies md ON md.module_id = im.id
        WHERE md.depends_on = $1 AND im.state = 'installed' AND md.optional = false
        "#
    )
    .bind(&module_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    if !dependents.is_empty() {
        let dep_names: Vec<String> = dependents.iter().map(|d| d.get::<String, _>("name")).collect();
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Cannot uninstall module".to_string(),
            error: Some(format!("The following modules depend on '{}': {}", name, dep_names.join(", "))),
        }).into_response();
    }

    // Update state to uninstalled
    let result = sqlx::query(
        "UPDATE installed_modules SET state = 'uninstalled', updated_at = NOW() WHERE technical_name = $1"
    )
    .bind(&module_id)
    .execute(&db)
    .await;

    match result {
        Ok(_) => {
            // Refresh installed modules cache
            let new_installed: Vec<String> = sqlx::query_scalar(
                "SELECT technical_name FROM installed_modules WHERE state = 'installed'"
            ).fetch_all(&db).await.unwrap_or_default();
            let mut cache = state.installed_modules.write().await;
            *cache = new_installed.into_iter().collect();
            drop(cache);

            let audit = AuditEntry::new(AuditAction::ModuleUnloaded, AuditSeverity::Warning)
                .with_user(vortex_common::UserId(user.id))
                .with_username(&user.username)
                .with_database(&db_ctx.db_name)
                .with_resource("module", module_id.clone())
                .with_resource_name(&name);
            if let Err(e) = state.audit.log(audit).await {
                error!("audit log for module uninstall failed: {}", e);
            }

            axum::Json(ModuleOperationResponse {
                success: true,
                message: format!("Module '{}' uninstalled successfully", name),
                error: None,
            }).into_response()
        }
        Err(e) => axum::Json(ModuleOperationResponse {
            success: false,
            message: "Uninstallation failed".to_string(),
            error: Some(e.to_string()),
        }).into_response(),
    }
}

async fn module_upgrade(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(module_id): Path<String>,
) -> Response {
    if !user.is_system_admin() {
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Permission denied".to_string(),
            error: Some("Only system administrators can upgrade modules".to_string()),
        }).into_response();
    }

    // Check if module exists and is installed
    let module = sqlx::query(
        "SELECT technical_name, name, state FROM installed_modules WHERE technical_name = $1"
    )
    .bind(&module_id)
    .fetch_optional(&db)
    .await;

    let module = match module {
        Ok(Some(m)) => m,
        Ok(None) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Module not found".to_string(),
                error: Some(format!("Module '{}' not found", module_id)),
            }).into_response();
        }
        Err(e) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Database error".to_string(),
                error: Some(e.to_string()),
            }).into_response();
        }
    };

    let name: String = module.get("name");
    let current_state: String = module.get("state");

    if current_state != "installed" {
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Module not installed".to_string(),
            error: Some(format!("Module '{}' is not installed", name)),
        }).into_response();
    }

    // Update timestamp
    let result = sqlx::query(
        "UPDATE installed_modules SET updated_at = NOW() WHERE technical_name = $1"
    )
    .bind(&module_id)
    .execute(&db)
    .await;

    match result {
        Ok(_) => axum::Json(ModuleOperationResponse {
            success: true,
            message: format!("Module '{}' upgraded successfully", name),
            error: None,
        }).into_response(),
        Err(e) => axum::Json(ModuleOperationResponse {
            success: false,
            message: "Upgrade failed".to_string(),
            error: Some(e.to_string()),
        }).into_response(),
    }
}

// ============================================================================
// Dynamic Sidebar Menu Helper
// ============================================================================

async fn build_sidebar_menu(db: &PgPool, user_roles: &[String], current_model: &str) -> String {
    // Fetch menu items
    let menus = sqlx::query(
        r#"SELECT id, name, parent_id, sequence, icon, action_type, action_model, action_view_type, action_url, groups
           FROM ir_ui_menu WHERE active = true ORDER BY sequence, name"#
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    // Icon mapping
    let get_icon = |icon: &str| -> &str {
        match icon {
            "dashboard" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>"#,
            "users" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m9 5.197v-1"/></svg>"#,
            "building" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>"#,
            "shield" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>"#,
            "lock" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>"#,
            "cog" | "settings" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>"#,
            "puzzle" | "apps" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z"/></svg>"#,
            "folder" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>"#,
            "user" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>"#,
            _ => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke-width="2"/></svg>"#,
        }
    };

    // Build hierarchical menu
    let mut html = String::new();

    // Get top-level menus (no parent)
    for menu in menus.iter().filter(|m| m.try_get::<Option<uuid::Uuid>, _>("parent_id").ok().flatten().is_none()) {
        let name: String = menu.get("name");
        let icon: Option<String> = menu.get("icon");
        let action_type: Option<String> = menu.get("action_type");
        let groups: Option<String> = menu.get("groups");

        // Check group permissions
        if let Some(ref g) = groups {
            if let Ok(allowed_groups) = serde_json::from_str::<Vec<String>>(g) {
                if !allowed_groups.is_empty() && !user_roles.iter().any(|r| allowed_groups.contains(r)) {
                    continue;
                }
            }
        }

        let menu_id: uuid::Uuid = menu.get("id");
        let icon_html = icon.as_deref().map(get_icon).unwrap_or("");

        // Check if this is a section header (no action) or a link
        if action_type.is_none() {
            // It's a section header - find children
            let children: Vec<_> = menus.iter()
                .filter(|m| m.try_get::<Option<uuid::Uuid>, _>("parent_id").ok().flatten() == Some(menu_id))
                .collect();

            if !children.is_empty() {
                html.push_str(&format!(r#"<li class="menu-title mt-4"><span>{}</span></li>"#, name));

                for child in children {
                    let child_name: String = child.get("name");
                    let child_icon: Option<String> = child.get("icon");
                    let child_action_type: Option<String> = child.get("action_type");
                    let child_action_model: Option<String> = child.get("action_model");
                    let child_action_url: Option<String> = child.get("action_url");
                    let child_view_type: String = child.try_get("action_view_type").unwrap_or_else(|_| "list".to_string());

                    let child_icon_html = child_icon.as_deref().map(get_icon).unwrap_or("");

                    let href = match child_action_type.as_deref() {
                        Some("model") => {
                            let model = child_action_model.unwrap_or_default();
                            let is_active = model == current_model;
                            let active_class = if is_active { " active" } else { "" };
                            format!(r#"<li><a href="/{}/{}" class="nav-item{}">{}<span class="sidebar-text">{}</span></a></li>"#,
                                child_view_type, model, active_class, child_icon_html, child_name)
                        }
                        Some("url") => {
                            let url = child_action_url.unwrap_or_default();
                            format!(r#"<li><a href="{}" class="nav-item">{}<span class="sidebar-text">{}</span></a></li>"#,
                                url, child_icon_html, child_name)
                        }
                        _ => format!(r#"<li><a class="nav-item">{}<span class="sidebar-text">{}</span></a></li>"#,
                            child_icon_html, child_name),
                    };
                    html.push_str(&href);
                }
            }
        } else {
            // It's a direct link (like Dashboard)
            let action_url: Option<String> = menu.get("action_url");
            let href = action_url.unwrap_or_else(|| "/home".to_string());
            html.push_str(&format!(r#"<li><a href="{}" class="nav-item">{}<span class="sidebar-text">{}</span></a></li>"#,
                href, icon_html, name));
        }
    }

    html
}

// ============================================================================
// Generic Model List View (Core Module)
// ============================================================================

#[derive(Debug, serde::Deserialize)]
struct GenericListQuery {
    search: Option<String>,
    group_by: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
    #[serde(flatten)]
    filters: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct ModelField {
    name: String,
    display_name: String,
    field_type: String,
    is_searchable: bool,
    is_filterable: bool,
    is_groupable: bool,
    selection_options: Option<serde_json::Value>,
    badge_colors: Option<serde_json::Value>,
    widget: Option<String>,
    related_model: Option<String>,
    related_field: Option<String>,
}

async fn generic_list_view(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Query(params): Query<GenericListQuery>,
) -> Response {
    // Fetch model metadata
    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name, list_url FROM ir_model WHERE name = $1 AND is_active = true"
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };

    // If a plugin has claimed a canonical list URL for this model (e.g.
    // the contacts plugin owns `/contacts`), defer to it. Keeps one source
    // of truth per model instead of competing list implementations.
    if let Ok(Some(custom_url)) = model_row.try_get::<Option<String>, _>("list_url") {
        if !custom_url.is_empty() {
            return Redirect::to(&custom_url).into_response();
        }
    }

    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let table_name: String = model_row.get("table_name");

    // Fetch field metadata
    let field_rows = sqlx::query(
        "SELECT name, display_name, field_type, is_searchable, is_filterable, is_groupable,
                selection_options, badge_colors, widget, related_model, related_field
         FROM ir_model_field WHERE model_id = $1 AND is_visible = true ORDER BY sequence"
    )
    .bind(model_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let fields: Vec<ModelField> = field_rows.iter().map(|r| ModelField {
        name: r.get("name"),
        display_name: r.get("display_name"),
        field_type: r.get("field_type"),
        is_searchable: r.get("is_searchable"),
        is_filterable: r.get("is_filterable"),
        is_groupable: r.get("is_groupable"),
        selection_options: r.get("selection_options"),
        badge_colors: r.get("badge_colors"),
        widget: r.get("widget"),
        related_model: r.get("related_model"),
        related_field: r.get("related_field"),
    }).collect();

    // Build WHERE conditions
    let mut conditions = vec!["1=1".to_string()];

    // Global search across searchable fields
    if let Some(ref search) = params.search {
        if !search.trim().is_empty() {
            let search_escaped = search.trim()
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
                .replace('\'', "''");
            let search_conditions: Vec<String> = fields.iter()
                .filter(|f| f.is_searchable && validate_identifier(&f.name))
                .map(|f| format!("{} ILIKE '%{}%'", f.name, search_escaped))
                .collect();
            if !search_conditions.is_empty() {
                conditions.push(format!("({})", search_conditions.join(" OR ")));
            }
        }
    }

    // Per-field filters
    for field in &fields {
        if field.is_filterable {
            let filter_key = format!("filter_{}", field.name);
            if let Some(filter_val) = params.filters.get(&filter_key) {
                if !filter_val.is_empty() {
                    let val_escaped = filter_val.replace("'", "''");
                    match field.field_type.as_str() {
                        "selection" => conditions.push(format!("{} = '{}'", field.name, val_escaped)),
                        "boolean" => {
                            if val_escaped == "true" {
                                conditions.push(format!("{} = true", field.name));
                            } else if val_escaped == "false" {
                                conditions.push(format!("{} = false", field.name));
                            }
                        }
                        _ => conditions.push(format!("{} ILIKE '%{}%'", field.name, val_escaped)),
                    }
                }
            }
        }
    }

    // Build ORDER BY with grouping
    let order_by = if let Some(ref group_by) = params.group_by {
        if fields.iter().any(|f| f.is_groupable && f.name == *group_by) {
            format!("{} NULLS LAST, name", group_by)
        } else {
            "name".to_string()
        }
    } else {
        "name".to_string()
    };

    // Build JOINs and SELECT for many2one fields
    let mut joins = String::new();
    let mut select_cols = format!("{}.*", table_name);
    let mut join_idx = 0;

    for field in &fields {
        if field.field_type == "many2one" {
            if let (Some(rel_model), Some(rel_field)) = (&field.related_model, &field.related_field) {
                let alias = format!("_rel{}", join_idx);
                joins.push_str(&format!(
                    " LEFT JOIN {} {} ON {}.{} = {}.id",
                    rel_model, alias, table_name, field.name, alias
                ));
                select_cols.push_str(&format!(", {}.{} AS {}_display", alias, rel_field, field.name));
                join_idx += 1;
            }
        }
    }

    // Pagination params
    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(80).max(10).min(500);
    let where_clause = conditions.join(" AND ");

    // Count total matching records
    let count_query = format!(
        "SELECT COUNT(*) FROM {}{} WHERE {}",
        table_name, joins, where_clause
    );
    let total: i64 = sqlx::query_scalar(&count_query)
        .fetch_one(&db)
        .await
        .unwrap_or(0);

    let offset = (page - 1) * per_page;

    // Build and execute query
    let query = format!(
        "SELECT {} FROM {}{} WHERE {} ORDER BY {} LIMIT {} OFFSET {}",
        select_cols, table_name, joins, where_clause, order_by, per_page, offset
    );

    let records = sqlx::query(&query)
        .fetch_all(&db)
        .await
        .unwrap_or_default();

    // Build table headers
    let headers: String = fields.iter()
        .take(6)
        .map(|f| format!("<th>{}</th>", f.display_name))
        .collect();

    // Build table rows
    let mut rows = String::new();
    let mut current_group = String::new();

    for record in &records {
        // Group header
        if let Some(ref group_by) = params.group_by {
            if let Some(field) = fields.iter().find(|f| f.name == *group_by) {
                let no_value_label = format!("No {}", field.display_name);
                let col_name = if field.field_type == "many2one" {
                    format!("{}_display", field.name)
                } else {
                    field.name.clone()
                };
                let group_val: String = match field.field_type.as_str() {
                    "boolean" => {
                        let v: bool = record.try_get(field.name.as_str()).unwrap_or(false);
                        if v { "Yes" } else { "No" }.to_string()
                    }
                    _ => {
                        let val = record.try_get::<String, _>(col_name.as_str()).unwrap_or_else(|_|
                            record.try_get::<Option<String>, _>(col_name.as_str()).ok().flatten().unwrap_or_default()
                        );
                        if val.is_empty() { no_value_label } else { val }
                    }
                };
                if group_val != current_group {
                    current_group = group_val.clone();
                    rows.push_str(&format!(
                        r#"<tr class="bg-base-200"><td colspan="6" class="font-bold text-sm uppercase tracking-wide py-2">{}</td></tr>"#,
                        current_group
                    ));
                }
            }
        }

        // Get record ID
        let id: uuid::Uuid = record.get("id");

        // Build cells
        let cells: String = fields.iter()
            .take(6)
            .map(|f| {
                let col_name = if f.field_type == "many2one" {
                    format!("{}_display", f.name)
                } else {
                    f.name.clone()
                };
                let cell_val = match f.field_type.as_str() {
                    "boolean" => {
                        let v: bool = record.try_get(f.name.as_str()).unwrap_or(false);
                        if v { "✓" } else { "-" }.to_string()
                    }
                    "selection" => {
                        let v: String = record.try_get(f.name.as_str()).unwrap_or_default();
                        if f.widget.as_deref() == Some("badge") {
                            if let Some(ref colors) = f.badge_colors {
                                let color = colors.get(&v).and_then(|c| c.as_str()).unwrap_or("ghost");
                                format!(r#"<span class="badge badge-{} badge-sm">{}</span>"#, color, v)
                            } else {
                                v
                            }
                        } else {
                            v
                        }
                    }
                    "many2one" => record.try_get::<String, _>(col_name.as_str()).unwrap_or_else(|_|
                        record.try_get::<Option<String>, _>(col_name.as_str()).ok().flatten().unwrap_or_else(|| "-".to_string())
                    ),
                    _ => record.try_get::<String, _>(col_name.as_str()).unwrap_or_else(|_|
                        record.try_get::<Option<String>, _>(col_name.as_str()).ok().flatten().unwrap_or_else(|| "-".to_string())
                    ),
                };
                format!("<td>{}</td>", cell_val)
            })
            .collect();

        rows.push_str(&format!(
            r#"<tr class="hover cursor-pointer" onclick="window.location='/{}/{}'">{}></tr>"#,
            model_name, id, cells
        ));
    }

    if rows.is_empty() {
        rows = format!(r#"<tr><td colspan="6" class="text-center py-8 opacity-60">No {} found.</td></tr>"#, model_display_name.to_lowercase());
    }

    // Build filter controls
    let mut filter_controls = String::new();

    // Search box
    filter_controls.push_str(&format!(
        r#"<div class="form-control">
            <label class="label py-0"><span class="label-text text-xs">Search</span></label>
            <input type="text" name="search" value="{}" placeholder="Search..." class="input input-bordered input-sm w-48"/>
        </div>"#,
        params.search.as_deref().unwrap_or("")
    ));

    // Group by dropdown
    let groupable_fields: Vec<&ModelField> = fields.iter().filter(|f| f.is_groupable).collect();
    if !groupable_fields.is_empty() {
        let group_options: String = groupable_fields.iter()
            .map(|f| {
                let selected = params.group_by.as_deref() == Some(&f.name);
                format!(r#"<option value="{}" {}>{}</option>"#, f.name, if selected { "selected" } else { "" }, f.display_name)
            })
            .collect();
        filter_controls.push_str(&format!(
            r#"<div class="form-control">
                <label class="label py-0"><span class="label-text text-xs">Group By</span></label>
                <select name="group_by" class="select select-bordered select-sm">
                    <option value="">None</option>
                    {}
                </select>
            </div>"#,
            group_options
        ));
    }

    // Per-field filters
    for field in fields.iter().filter(|f| f.is_filterable) {
        let filter_key = format!("filter_{}", field.name);
        let current_val = params.filters.get(&filter_key).map(|s| s.as_str()).unwrap_or("");

        match field.field_type.as_str() {
            "selection" => {
                if let Some(ref opts) = field.selection_options {
                    if let Some(arr) = opts.as_array() {
                        let options: String = arr.iter()
                            .filter_map(|o| {
                                let val = o.get("value")?.as_str()?;
                                let label = o.get("label")?.as_str()?;
                                let selected = current_val == val;
                                Some(format!(r#"<option value="{}" {}>{}</option>"#, val, if selected { "selected" } else { "" }, label))
                            })
                            .collect();
                        filter_controls.push_str(&format!(
                            r#"<div class="form-control">
                                <label class="label py-0"><span class="label-text text-xs">{}</span></label>
                                <select name="{}" class="select select-bordered select-sm">
                                    <option value="">All</option>
                                    {}
                                </select>
                            </div>"#,
                            field.display_name, filter_key, options
                        ));
                    }
                }
            }
            "boolean" => {
                filter_controls.push_str(&format!(
                    r#"<div class="form-control">
                        <label class="label py-0"><span class="label-text text-xs">{}</span></label>
                        <select name="{}" class="select select-bordered select-sm">
                            <option value="">All</option>
                            <option value="true" {}>Yes</option>
                            <option value="false" {}>No</option>
                        </select>
                    </div>"#,
                    field.display_name, filter_key,
                    if current_val == "true" { "selected" } else { "" },
                    if current_val == "false" { "selected" } else { "" }
                ));
            }
            _ => {
                filter_controls.push_str(&format!(
                    r#"<div class="form-control">
                        <label class="label py-0"><span class="label-text text-xs">{}</span></label>
                        <input type="text" name="{}" value="{}" placeholder="Filter..." class="input input-bordered input-sm w-32"/>
                    </div>"#,
                    field.display_name, filter_key, current_val
                ));
            }
        }
    }

    // Build dynamic sidebar
    let sidebar_menu = build_sidebar_menu(&db, &user.roles, &model_name).await;

    // Fetch saved filters for this model
    let saved_filters = sqlx::query(
        "SELECT id, name FROM ir_filters WHERE model_id = $1 AND active = true AND (user_id IS NULL OR user_id = $2) ORDER BY name"
    )
    .bind(model_id)
    .bind(user.id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let saved_filters_options: String = saved_filters.iter().map(|f| {
        let id: uuid::Uuid = f.get("id");
        let name: String = f.get("name");
        format!(r#"<option value="{}">{}</option>"#, id, name)
    }).collect();

    // Build full page
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>{}</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script>
<style>
body {{ background: oklch(var(--b2)); color: oklch(var(--bc)); }}
.top-navbar {{ background: oklch(var(--b1)); border-bottom: 1px solid oklch(var(--b3)); position: sticky; top: 0; z-index: 50; }}
.sidebar {{ background: oklch(var(--b1)); border-right: 1px solid oklch(var(--b3)); }}
.card {{ background: oklch(var(--b1)); border: 1px solid oklch(var(--b3)); }}
.table {{ color: oklch(var(--bc)); }}
.table th {{ color: #8BC53F; font-weight: 600; background: oklch(var(--b1)); }}
.table tr:hover {{ background: oklch(var(--b3)); }}
.menu a {{ color: oklch(var(--bc)/0.7); }}
.menu a:hover, .menu a.active {{ background: oklch(var(--b3)); color: oklch(var(--bc)); }}
.text-muted {{ color: oklch(var(--bc)/0.6); }}
.btn-primary {{ background: #8BC53F; border-color: #8BC53F; color: #000; }}
.btn-primary:hover {{ background: #6BA32E; border-color: #6BA32E; }}
.user-badge {{ background: #8BC53F; color: #000; font-weight: 600; }}
@media (max-width: 768px) {{
    .sidebar {{ display: none; }}
    .main-content {{ padding: 1rem; }}
    .table {{ font-size: 0.85rem; }}
    h1 {{ font-size: 1.5rem; }}
}}
</style>
</head><body class="min-h-screen">
<nav class="top-navbar px-4 py-3 flex items-center justify-between">
    <div class="flex items-center gap-2"><button class="btn btn-ghost btn-sm btn-square md:hidden" onclick="var s=document.querySelector('.sidebar');s.classList.toggle('hidden');s.classList.toggle('md:block')"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a></div>
    <div class="flex items-center gap-2 md:gap-3">
        <a href="/home" class="text-base-content text-sm hover:underline hidden md:inline">Home</a>
        <a href="/settings" class="text-base-content text-sm hover:underline hidden md:inline">Settings</a>
        <a href="/notifications" class="btn btn-ghost btn-circle btn-sm relative" title="Notifications">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
            <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
        </a>
        <button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-circle btn-sm" title="Toggle theme"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button>
        <div class="user-badge px-3 py-1 rounded-full text-sm">@{}</div>
    </div>
</nav>
<div class="flex">
<aside class="sidebar w-64 min-h-screen p-4 hidden md:block">
<ul class="menu mt-2">
{}
</ul>
</aside>
<main class="flex-1 p-4 md:p-6 main-content">
<div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
<div><h1 class="text-xl md:text-2xl font-bold">{}</h1><p class="text-muted">Manage {}</p></div>
<div class="flex gap-2 flex-wrap">
    <div class="btn-group">
        <a href="/list/{}" class="btn btn-sm btn-active" title="List View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
        </a>
        <a href="/kanban/{}" class="btn btn-sm" title="Kanban View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>
        </a>
        <a href="/graph/{}" class="btn btn-sm" title="Graph View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
        </a>
        <a href="/pivot/{}" class="btn btn-sm" title="Pivot View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
        </a>
    </div>
    <a href="/{}/new" class="btn btn-primary btn-sm">+ New</a>
</div>
</div>
<div class="card mb-4">
<div class="card-body p-3 md:p-4">
<form method="GET" action="/list/{}" class="flex flex-wrap gap-3 items-end">
    <div class="form-control">
        <label class="label py-0"><span class="label-text text-xs text-muted">Saved Filters</span></label>
        <select class="select select-bordered select-sm bg-transparent" onchange="if(this.value) window.location='?saved_filter='+this.value">
            <option value="">-- Select --</option>
            {}
        </select>
    </div>
    <div class="divider divider-horizontal mx-1 hidden md:flex"></div>
    {}
    <button type="submit" class="btn btn-sm btn-primary">Apply</button>
    <a href="/list/{}" class="btn btn-sm btn-ghost">Clear</a>
</form>
</div>
</div>
<div class="card overflow-x-auto">
<table class="table">
<thead><tr>{}</tr></thead>
<tbody>{}</tbody>
</table>
{}
</div>
</main>
</div>
</body></html>"#,
        model_display_name,
        user.username,
        sidebar_menu,
        model_display_name, model_display_name.to_lowercase(),
        model_name, model_name, model_name, model_name, model_name, model_name,
        saved_filters_options, filter_controls, model_name, headers, rows,
        {
            // Build base_url for pagination links, preserving search/filter/group_by/per_page params
            let mut base_parts = vec![format!("/list/{}", model_name)];
            let mut qp = Vec::new();
            if let Some(ref s) = params.search {
                if !s.is_empty() {
                    qp.push(format!("search={}", html_escape(s)));
                }
            }
            if let Some(ref g) = params.group_by {
                if !g.is_empty() {
                    qp.push(format!("group_by={}", html_escape(g)));
                }
            }
            for (k, v) in &params.filters {
                if !v.is_empty() {
                    qp.push(format!("{}={}", html_escape(k), html_escape(v)));
                }
            }
            if per_page != 80 {
                qp.push(format!("per_page={}", per_page));
            }
            let base_url = if qp.is_empty() {
                base_parts.remove(0)
            } else {
                format!("{}?{}", base_parts[0], qp.join("&"))
            };
            build_pagination_html(page, per_page, total, &base_url)
        }
    )).into_response()
}

// ============================================================================
// Saved analytic views (Initiative #4)
// ============================================================================
// Persist a pivot/graph/kanban/calendar configuration as an owner/shared user
// record so operators can name and revisit a breakdown. See
// vortex_framework::saved_views for the registry-checked config model.

/// Pull the `cfg_<key>` fields out of a posted view-save form into a raw config
/// bag (the module re-validates every key against the registry).
fn collect_view_config(
    form: &std::collections::HashMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    form.iter()
        .filter_map(|(k, v)| k.strip_prefix("cfg_").map(|key| (key.to_string(), v.clone())))
        .filter(|(_, v)| !v.trim().is_empty())
        .collect()
}

/// POST /views/save — validate and persist the current analytic view config,
/// then redirect back to that view with the saved config applied.
async fn saved_view_save(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let model = form.get("model").map(String::as_str).unwrap_or("");
    let view_type = form.get("view_type").map(String::as_str).unwrap_or("");
    let name = form.get("name").map(String::as_str).unwrap_or("");
    let is_shared = form.get("is_shared").map(|v| v == "1" || v == "on").unwrap_or(false);
    let is_default = form.get("is_default").map(|v| v == "1" || v == "on").unwrap_or(false);
    let fallback = format!("/{}/{}", view_type, model);
    let redirect = form.get("redirect").map(String::as_str).filter(|s| s.starts_with('/')).unwrap_or(&fallback);
    let raw = collect_view_config(&form);

    match vortex_framework::saved_views::create(
        &db, model, view_type, name, &raw, user.id, is_shared, is_default,
    )
    .await
    {
        Ok(id) => match vortex_framework::saved_views::load(&db, id).await {
            // Land on the freshly saved view so the user sees it applied.
            Some(v) => {
                let qs = v.query_string();
                let target = if qs.is_empty() { fallback.clone() } else { format!("/{}/{}?{}", view_type, model, qs) };
                vortex_framework::flash::flash_redirect(
                    &target,
                    vortex_framework::flash::FlashKind::Success,
                    &format!("Saved view “{}”.", v.name),
                )
            }
            None => Redirect::to(redirect).into_response(),
        },
        Err(e) => {
            // Bounce back to the view with the error surfaced as a toast.
            vortex_framework::flash::flash_redirect(
                redirect,
                vortex_framework::flash::FlashKind::Error,
                &e,
            )
        }
    }
}

/// POST /views/{id}/delete — remove a saved view the user owns (or any, if admin).
async fn saved_view_delete(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let redirect = form.get("redirect").map(String::as_str).filter(|s| s.starts_with('/')).unwrap_or("/home").to_string();
    match vortex_framework::saved_views::load(&db, id).await {
        Some(v) if v.can_edit(user.id, user.is_admin()) => {
            let _ = vortex_framework::saved_views::delete(&db, id).await;
        }
        _ => return (StatusCode::FORBIDDEN, "Not permitted").into_response(),
    }
    Redirect::to(&redirect).into_response()
}

// ============================================================================
// Generic Kanban View
// ============================================================================

async fn generic_kanban_view(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Fetch model metadata
    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name FROM ir_model WHERE name = $1 AND is_active = true"
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };

    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let table_name: String = model_row.get("table_name");

    // Kanban grouping: query param → shared default saved view → none. This
    // replaces the never-created ir_ui_view_kanban join; card title stays the
    // conventional `name` (records are grouped in-memory, so the column name is
    // only ever used as a safe map key, never interpolated into SQL).
    let default_cfg = vortex_framework::saved_views::default_config_for(&db, &model_name, "kanban")
        .await
        .unwrap_or_default();
    let title_field = "name".to_string();
    let subtitle_field: Option<String> = None;
    let tags_field: Option<String> = None;
    let group_by_field: Option<String> = params
        .get("group_by")
        .cloned()
        .or_else(|| default_cfg.get("group_by").cloned());

    // Saved-views toolbar config (only a chosen grouping is worth saving).
    let mut current_cfg = std::collections::BTreeMap::new();
    if let Some(g) = &group_by_field {
        current_cfg.insert("group_by".to_string(), g.clone());
    }
    let view_bar = vortex_framework::saved_views::render_view_bar(
        &db, &model_name, "kanban", &current_cfg, user.id, user.is_admin(),
    )
    .await;

    // Fetch field metadata for grouping field options
    let group_options: Vec<(String, String)> = if let Some(ref group_field) = group_by_field {
        let field_meta = sqlx::query(
            "SELECT selection_options FROM ir_model_field WHERE model_id = $1 AND name = $2"
        )
        .bind(model_id)
        .bind(group_field)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

        if let Some(row) = field_meta {
            let opts: Option<serde_json::Value> = row.get("selection_options");
            opts.as_ref()
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|o| {
                            let val = o.get("value")?.as_str()?;
                            let label = o.get("label")?.as_str()?;
                            Some((val.to_string(), label.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    // Fetch records
    if !validate_identifier(&table_name) {
        return (StatusCode::BAD_REQUEST, Html("Invalid model".to_string())).into_response();
    }
    let query = format!("SELECT * FROM {} WHERE active = true ORDER BY name LIMIT 200", table_name);
    let records = sqlx::query(&query)
        .fetch_all(&db)
        .await
        .unwrap_or_default();

    // Group records by the group_by_field
    let mut columns: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    // Initialize columns from group_options
    for (val, _label) in &group_options {
        columns.insert(val.clone(), Vec::new());
    }

    // Build cards and group them
    for record in &records {
        let id: uuid::Uuid = record.get("id");
        let title: String = record.try_get(title_field.as_str()).unwrap_or_default();
        let subtitle: String = subtitle_field.as_ref()
            .and_then(|f| record.try_get::<Option<String>, _>(f.as_str()).ok().flatten())
            .unwrap_or_default();
        let tag_value: String = tags_field.as_ref()
            .and_then(|f| record.try_get::<String, _>(f.as_str()).ok())
            .unwrap_or_default();
        let group_value: String = group_by_field.as_ref()
            .and_then(|f| record.try_get::<String, _>(f.as_str()).ok())
            .unwrap_or_else(|| "other".to_string());

        let tag_badge = match tag_value.as_str() {
            "approved" => r#"<span class="badge badge-success badge-xs">Approved</span>"#,
            "draft" => r#"<span class="badge badge-warning badge-xs">Draft</span>"#,
            _ => "",
        };

        let card_html = format!(
            r#"<div class="card bg-base-100 shadow-sm mb-2 cursor-pointer hover:shadow-md transition-shadow" onclick="window.location='/{}/{}'">
                <div class="card-body p-3">
                    <h3 class="card-title text-sm">{}</h3>
                    <p class="text-xs opacity-60">{}</p>
                    <div class="mt-1">{}</div>
                </div>
            </div>"#,
            model_name, id, title, subtitle, tag_badge
        );

        columns.entry(group_value).or_insert_with(Vec::new).push(card_html);
    }

    // Build column HTML
    let mut columns_html = String::new();
    for (val, label) in &group_options {
        let cards = columns.get(val).map(|v| v.join("")).unwrap_or_default();
        let count = columns.get(val).map(|v| v.len()).unwrap_or(0);
        columns_html.push_str(&format!(
            r#"<div class="flex-1 min-w-[280px] max-w-[320px]">
                <div class="bg-base-200 rounded-lg p-3">
                    <div class="flex justify-between items-center mb-3">
                        <h3 class="font-semibold text-sm uppercase tracking-wide">{}</h3>
                        <span class="badge badge-ghost badge-sm">{}</span>
                    </div>
                    <div class="space-y-2 min-h-[100px]">
                        {}
                    </div>
                </div>
            </div>"#,
            label, count, cards
        ));
    }

    // Build dynamic sidebar
    let sidebar_menu = build_sidebar_menu(&db, &user.roles, &model_name).await;

    // Build full page
    let html = format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>{} - Kanban</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script>
<style>
body {{ background: oklch(var(--b2)); color: oklch(var(--bc)); }}
.top-navbar {{ background: oklch(var(--b1)); border-bottom: 1px solid oklch(var(--b3)); position: sticky; top: 0; z-index: 50; }}
.sidebar {{ background: oklch(var(--b1)); border-right: 1px solid oklch(var(--b3)); }}
.card {{ background: oklch(var(--b1)); border: 1px solid oklch(var(--b3)); }}
.text-muted {{ color: oklch(var(--bc)/0.6); }}
.user-badge {{ background: #8BC53F; color: #000; font-weight: 600; }}
.kanban-col {{ background: oklch(var(--b1)); }}
@media (max-width: 768px) {{ .sidebar {{ display: none; }} }}
</style>
</head><body class="min-h-screen">
<nav class="top-navbar px-4 py-3 flex items-center justify-between">
    <div class="flex items-center gap-2"><button class="btn btn-ghost btn-sm btn-square md:hidden" onclick="var s=document.querySelector('.sidebar');s.classList.toggle('hidden');s.classList.toggle('md:block')"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a></div>
    <div class="flex items-center gap-2 md:gap-3">
        <a href="/home" class="text-base-content text-sm hover:underline hidden md:inline">Home</a>
        <a href="/settings" class="text-base-content text-sm hover:underline hidden md:inline">Settings</a>
        <a href="/notifications" class="btn btn-ghost btn-circle btn-sm relative" title="Notifications">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
            <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
        </a>
        <button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-circle btn-sm" title="Toggle theme"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button>
        <div class="user-badge px-3 py-1 rounded-full text-sm">@{}</div>
    </div>
</nav>
<div class="flex">
<aside class="sidebar w-64 min-h-screen p-4 hidden md:block">
<ul class="menu mt-2">
{}
</ul>
</aside>
<main class="flex-1 p-4 md:p-6">
<div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
<div><h1 class="text-xl md:text-2xl font-bold">{}</h1><p class="text-muted">Kanban view</p></div>
<div class="flex gap-2 flex-wrap">
    <div class="btn-group">
        <a href="/list/{}" class="btn btn-sm" title="List View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
        </a>
        <a href="/kanban/{}" class="btn btn-sm btn-active" title="Kanban View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>
        </a>
        <a href="/graph/{}" class="btn btn-sm" title="Graph View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
        </a>
        <a href="/pivot/{}" class="btn btn-sm" title="Pivot View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
        </a>
    </div>
    <!--VIEW_BAR-->
    <a href="/{}/new" class="btn btn-primary btn-sm" style="background:#8BC53F;border-color:#8BC53F;color:#000">+ New</a>
</div>
</div>
<div class="flex gap-4 overflow-x-auto pb-4">
{}
</div>
</main>
</div>
</body></html>"#,
        model_display_name,
        user.username,
        sidebar_menu,
        model_display_name,
        model_name, model_name, model_name, model_name, model_name,
        columns_html
    );
    Html(html.replace("<!--VIEW_BAR-->", &view_bar)).into_response()
}

// ============================================================================
// Generic Graph View
// ============================================================================

async fn generic_graph_view(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Fetch model metadata
    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name FROM ir_model WHERE name = $1 AND is_active = true"
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };

    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let table_name: String = model_row.get("table_name");
    if !validate_identifier(&table_name) {
        return (StatusCode::BAD_REQUEST, Html("Invalid model".to_string())).into_response();
    }

    // Registered field names — the allow-list the group-by column must be in, so
    // it can never become an arbitrary SQL fragment.
    let field_list: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM ir_model_field WHERE model_id = $1 ORDER BY sequence, name",
    )
    .bind(model_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let field_set: std::collections::HashSet<&str> = field_list.iter().map(String::as_str).collect();

    // Config precedence: explicit query params → shared default saved view →
    // sensible fallback. This replaces the never-created ir_ui_view join.
    let default_cfg = vortex_framework::saved_views::default_config_for(&db, &model_name, "graph")
        .await
        .unwrap_or_default();
    let pick = |key: &str| params.get(key).cloned().or_else(|| default_cfg.get(key).cloned());

    let graph_type = match pick("type") {
        Some(t) if vortex_framework::saved_views::GRAPH_TYPES.iter().any(|(c, _)| *c == t) => t,
        _ => "bar".to_string(),
    };
    // Must be a real, registered column; else fall back to the first field so the
    // page still renders (never interpolate an unvalidated identifier).
    let group_by_field = pick("group_by")
        .filter(|g| field_set.contains(g.as_str()))
        .or_else(|| {
            ["contact_type", "state", "record_state"]
                .iter()
                .find(|c| field_set.contains(**c))
                .map(|c| c.to_string())
                .or_else(|| field_list.first().cloned())
        })
        .unwrap_or_else(|| "id".to_string());

    // The config in effect right now, for the "Save current view" action.
    let mut current_cfg = std::collections::BTreeMap::new();
    current_cfg.insert("group_by".to_string(), group_by_field.clone());
    current_cfg.insert("type".to_string(), graph_type.clone());
    let view_bar = vortex_framework::saved_views::render_view_bar(
        &db, &model_name, "graph", &current_cfg, user.id, user.is_admin(),
    )
    .await;

    // Get counts grouped by field
    let query = format!(
        "SELECT {}, COUNT(*) as count FROM {} WHERE active = true GROUP BY {} ORDER BY count DESC",
        group_by_field, table_name, group_by_field
    );
    let results = sqlx::query(&query)
        .fetch_all(&db)
        .await
        .unwrap_or_default();

    // Build chart data
    let mut labels = Vec::new();
    let mut data = Vec::new();
    let colors = ["#22c55e", "#3b82f6", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"];

    for (i, row) in results.iter().enumerate() {
        let label: String = row.try_get(group_by_field.as_str()).unwrap_or_else(|_| "Other".to_string());
        let count: i64 = row.get("count");
        labels.push(format!("\"{}\"", label));
        data.push(count.to_string());
    }

    let labels_json = labels.join(", ");
    let data_json = data.join(", ");
    let colors_json = colors.iter().take(data.len()).map(|c| format!("\"{}\"", c)).collect::<Vec<_>>().join(", ");

    // Build dynamic sidebar
    let sidebar_menu = build_sidebar_menu(&db, &user.roles, &model_name).await;

    let html = format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>{} - Graph</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script>
<script src="/static/vendor/chart.umd.js"></script>
<style>
body {{ background: oklch(var(--b2)); color: oklch(var(--bc)); }}
.top-navbar {{ background: oklch(var(--b1)); border-bottom: 1px solid oklch(var(--b3)); position: sticky; top: 0; z-index: 50; }}
.sidebar {{ background: oklch(var(--b1)); border-right: 1px solid oklch(var(--b3)); }}
.card {{ background: oklch(var(--b1)); border: 1px solid oklch(var(--b3)); }}
.text-muted {{ color: oklch(var(--bc)/0.6); }}
.user-badge {{ background: #8BC53F; color: #000; font-weight: 600; }}
@media (max-width: 768px) {{ .sidebar {{ display: none; }} .chart-grid {{ grid-template-columns: 1fr; }} }}
</style>
</head><body class="min-h-screen">
<nav class="top-navbar px-4 py-3 flex items-center justify-between">
    <div class="flex items-center gap-2"><button class="btn btn-ghost btn-sm btn-square md:hidden" onclick="var s=document.querySelector('.sidebar');s.classList.toggle('hidden');s.classList.toggle('md:block')"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a></div>
    <div class="flex items-center gap-2 md:gap-3">
        <a href="/home" class="text-base-content text-sm hover:underline hidden md:inline">Home</a>
        <a href="/settings" class="text-base-content text-sm hover:underline hidden md:inline">Settings</a>
        <a href="/notifications" class="btn btn-ghost btn-circle btn-sm relative" title="Notifications">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
            <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
        </a>
        <button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-circle btn-sm" title="Toggle theme"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button>
        <div class="user-badge px-3 py-1 rounded-full text-sm">@{}</div>
    </div>
</nav>
<div class="flex">
<aside class="sidebar w-64 min-h-screen p-4 hidden md:block">
<ul class="menu mt-2">
{}
</ul>
</aside>
<main class="flex-1 p-4 md:p-6">
<div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
<div><h1 class="text-xl md:text-2xl font-bold">{}</h1><p class="text-muted">Graph view - by {}</p></div>
<div class="flex gap-2 flex-wrap">
    <div class="btn-group">
        <a href="/list/{}" class="btn btn-sm" title="List View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
        </a>
        <a href="/kanban/{}" class="btn btn-sm" title="Kanban View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>
        </a>
        <a href="/graph/{}" class="btn btn-sm btn-active" title="Graph View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
        </a>
        <a href="/pivot/{}" class="btn btn-sm" title="Pivot View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
        </a>
    </div>
    <!--VIEW_BAR-->
    <a href="/{}/new" class="btn btn-primary btn-sm" style="background:#8BC53F;border-color:#8BC53F;color:#000">+ New</a>
</div>
</div>
<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6 chart-grid">
<div class="card">
<div class="card-body">
<h2 class="card-title text-sm">By {}</h2>
<canvas id="barChart"></canvas>
</div>
</div>
<div class="card">
<div class="card-body">
<h2 class="card-title text-sm">Distribution</h2>
<canvas id="pieChart"></canvas>
</div>
</div>
</div>
</main>
</div>
<script>
const labels = [{}];
const data = [{}];
const colors = [{}];

new Chart(document.getElementById('barChart'), {{
    type: '{}',
    data: {{
        labels: labels,
        datasets: [{{
            label: 'Count',
            data: data,
            backgroundColor: colors,
            borderColor: colors,
            borderWidth: 1
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{ y: {{ beginAtZero: true }} }}
    }}
}});

new Chart(document.getElementById('pieChart'), {{
    type: 'doughnut',
    data: {{
        labels: labels,
        datasets: [{{
            data: data,
            backgroundColor: colors
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{ legend: {{ position: 'bottom' }} }}
    }}
}});
</script>
</body></html>"#,
        model_display_name,
        user.username,
        sidebar_menu,
        model_display_name, group_by_field,
        model_name, model_name, model_name, model_name, model_name,
        group_by_field,
        labels_json, data_json, colors_json,
        graph_type
    );
    Html(html.replace("<!--VIEW_BAR-->", &view_bar)).into_response()
}

// ============================================================================
// Calendar View
// ============================================================================

async fn generic_calendar_view(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Fetch model metadata
    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name FROM ir_model WHERE name = $1 AND is_active = true"
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };

    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let table_name: String = model_row.get("table_name");
    if !validate_identifier(&table_name) {
        return (StatusCode::BAD_REQUEST, Html("Invalid model".to_string())).into_response();
    }

    // Candidate date columns (registry) — the calendar axis must be one of these
    // real date/datetime fields, so it is safe to interpolate. (The registry
    // column is `name`; the old query used a non-existent `field_name` and so
    // always fell back to created_at.)
    let date_fields: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM ir_model_field WHERE model_id = $1 AND field_type IN ('date', 'datetime') ORDER BY sequence, name",
    )
    .bind(model_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Axis: query param → shared default saved view → first date field →
    // created_at. Replaces the never-created ir_ui_view calendar config.
    let default_cfg = vortex_framework::saved_views::default_config_for(&db, &model_name, "calendar")
        .await
        .unwrap_or_default();
    let date_field: String = params
        .get("date_field")
        .cloned()
        .or_else(|| default_cfg.get("date_field").cloned())
        .filter(|d| date_fields.iter().any(|f| f == d))
        .or_else(|| date_fields.first().cloned())
        .unwrap_or_else(|| "created_at".to_string());

    // Find name/title field (registry column is `name`).
    let name_field: String = sqlx::query_scalar(
        "SELECT name FROM ir_model_field WHERE model_id = $1 AND name IN ('name', 'title', 'subject') LIMIT 1"
    )
    .bind(model_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "id".to_string());

    // Saved-views toolbar config.
    let mut current_cfg = std::collections::BTreeMap::new();
    current_cfg.insert("date_field".to_string(), date_field.clone());
    let view_bar = vortex_framework::saved_views::render_view_bar(
        &db, &model_name, "calendar", &current_cfg, user.id, user.is_admin(),
    )
    .await;

    // Parse year/month from query params or use current
    let now = chrono::Utc::now();
    let year: i32 = params.get("year").and_then(|y| y.parse().ok()).unwrap_or(now.year());
    let month: u32 = params.get("month").and_then(|m| m.parse().ok()).unwrap_or(now.month());

    // Calculate first and last day of month
    let first_day = chrono::NaiveDate::from_ymd_opt(year, month, 1).unwrap();
    let last_day = if month == 12 {
        chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap().pred_opt().unwrap()
    } else {
        chrono::NaiveDate::from_ymd_opt(year, month + 1, 1).unwrap().pred_opt().unwrap()
    };

    // Fetch records for this month
    let query = format!(
        "SELECT id, {}, {}::date as event_date FROM {} WHERE {}::date >= $1 AND {}::date <= $2 ORDER BY {} ASC",
        name_field, date_field, table_name, date_field, date_field, date_field
    );
    let records = sqlx::query(&query)
        .bind(first_day)
        .bind(last_day)
        .fetch_all(&db)
        .await
        .unwrap_or_default();

    // Group records by date
    let mut events_by_date: std::collections::HashMap<chrono::NaiveDate, Vec<(uuid::Uuid, String)>> = std::collections::HashMap::new();
    for row in &records {
        let id: uuid::Uuid = row.get("id");
        let name: String = row.try_get(&name_field as &str).unwrap_or_else(|_| id.to_string());
        let date: chrono::NaiveDate = row.get("event_date");
        events_by_date.entry(date).or_default().push((id, name));
    }

    // Build calendar grid
    let weekday_of_first = first_day.weekday().num_days_from_sunday();
    let days_in_month = last_day.day();

    let mut calendar_cells = String::new();

    // Empty cells before first day
    for _ in 0..weekday_of_first {
        calendar_cells.push_str(r#"<div class="h-24 bg-base-200/50"></div>"#);
    }

    // Days of month
    for day in 1..=days_in_month {
        let date = chrono::NaiveDate::from_ymd_opt(year, month, day).unwrap();
        let is_today = date == now.date_naive();
        let today_class = if is_today { "ring-2 ring-primary" } else { "" };

        let mut events_html = String::new();
        if let Some(events) = events_by_date.get(&date) {
            for (id, name) in events.iter().take(3) {
                events_html.push_str(&format!(
                    r##"<a href="/{}/{}" class="block text-xs bg-primary/20 text-primary rounded px-1 py-0.5 truncate hover:bg-primary/30">{}</a>"##,
                    model_name, id, name
                ));
            }
            if events.len() > 3 {
                events_html.push_str(&format!(
                    r#"<span class="text-xs text-base-content/50">+{} more</span>"#,
                    events.len() - 3
                ));
            }
        }

        calendar_cells.push_str(&format!(
            r#"<div class="h-24 bg-base-100 p-1 border border-base-300 {}">
                <div class="font-semibold text-sm {}">{}</div>
                <div class="space-y-0.5 mt-1">{}</div>
            </div>"#,
            today_class,
            if is_today { "text-primary" } else { "" },
            day,
            events_html
        ));
    }

    // Empty cells after last day
    let total_cells = weekday_of_first + days_in_month;
    let remaining = (7 - (total_cells % 7)) % 7;
    for _ in 0..remaining {
        calendar_cells.push_str(r#"<div class="h-24 bg-base-200/50"></div>"#);
    }

    // Navigation links
    let (prev_year, prev_month) = if month == 1 { (year - 1, 12) } else { (year, month - 1) };
    let (next_year, next_month) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };

    let month_names = ["", "January", "February", "March", "April", "May", "June",
                       "July", "August", "September", "October", "November", "December"];
    let month_name = month_names[month as usize];

    // Build dynamic sidebar
    let sidebar_menu = build_sidebar_menu(&db, &user.roles, &model_name).await;

    let html = format!(r##"<!DOCTYPE html>
<html data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <title>{} - Calendar</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
    <script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar-inline').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay-inline').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay-inline" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar-inline').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">
    <aside id="sidebar-inline" class="w-64 bg-base-100 shadow-lg min-h-screen p-4 fixed lg:static top-0 left-0 z-40 h-full -translate-x-full lg:translate-x-0 transition-transform duration-200">
        <div class="text-xl font-bold mb-6"><span class="text-success">re</span><span class="opacity-60">micle</span></div>
        <ul class="menu">{}</ul>
    </aside>
    <main class="flex-1 p-4 lg:p-6 min-w-0">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">{}</h1>
                <p class="opacity-60">Calendar view - by {}</p>
            </div>
            <div class="flex gap-2">
                <div class="btn-group">
                    <a href="/list/{}" class="btn btn-sm" title="List View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
                    </a>
                    <a href="/kanban/{}" class="btn btn-sm" title="Kanban View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>
                    </a>
                    <a href="/graph/{}" class="btn btn-sm" title="Graph View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                    </a>
                    <a href="/calendar/{}" class="btn btn-sm btn-active" title="Calendar View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                    </a>
                </div>
                <!--VIEW_BAR-->
                <a href="/{}/new" class="btn btn-primary btn-sm">+ New</a>
            </div>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body">
                <div class="flex justify-between items-center mb-4">
                    <a href="/calendar/{}?year={}&month={}" class="btn btn-ghost btn-sm">← Prev</a>
                    <h2 class="text-xl font-bold">{} {}</h2>
                    <a href="/calendar/{}?year={}&month={}" class="btn btn-ghost btn-sm">Next →</a>
                </div>
                <div class="grid grid-cols-7 gap-px">
                    <div class="text-center font-semibold py-2 bg-base-200">Sun</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Mon</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Tue</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Wed</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Thu</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Fri</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Sat</div>
                    {}
                </div>
            </div>
        </div>
    </main>
</div>
</body>
</html>"##,
        model_display_name,
        sidebar_menu,
        model_display_name, date_field,
        model_name, model_name, model_name, model_name, model_name,
        model_name, prev_year, prev_month,
        month_name, year,
        model_name, next_year, next_month,
        calendar_cells
    );
    Html(html.replace("<!--VIEW_BAR-->", &view_bar)).into_response()
}

// ============================================================================
// Generic Pivot View (Excel-style, client-rendered)
// ============================================================================
// The page ships a drag-and-drop PivotTable-Fields pane (see /static/pivot.js);
// aggregation happens server-side in `generic_pivot_data`, which returns a JSON
// matrix with subtotals/grand-totals computed by SQL ROLLUP.

async fn generic_pivot_view(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    use vortex_framework::ui::html_escape;

    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name, list_url FROM ir_model WHERE name = $1 AND is_active = true",
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };
    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let list_view_url: String = model_row
        .try_get::<Option<String>, _>("list_url")
        .ok()
        .flatten()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| format!("/list/{}", model_name));

    // Fields for the pane: groupable dimensions + numeric measures.
    let fields = sqlx::query(
        "SELECT name, field_type, display_name FROM ir_model_field WHERE model_id = $1 ORDER BY sequence, name",
    )
    .bind(model_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut field_arr: Vec<serde_json::Value> = Vec::new();
    for f in &fields {
        let name: String = f.get("name");
        let ftype: String = f.get("field_type");
        let label: String = f.get("display_name");
        let numeric = matches!(ftype.as_str(), "integer" | "float" | "decimal" | "monetary" | "number");
        let groupable = matches!(
            ftype.as_str(),
            "selection" | "string" | "char" | "many2one" | "boolean" | "date" | "datetime"
        );
        if groupable || numeric {
            field_arr.push(serde_json::json!({"name": name, "label": label, "numeric": numeric}));
        }
    }
    let fields_json = serde_json::to_string(&field_arr).unwrap_or_else(|_| "[]".to_string());

    // Initial config: query params win, else the shared default saved view.
    let default_cfg = vortex_framework::saved_views::default_config_for(&db, &model_name, "pivot")
        .await
        .unwrap_or_default();
    let pick = |k: &str| params.get(k).cloned().or_else(|| default_cfg.get(k).cloned());
    let rows_v = pick("rows").unwrap_or_default();
    let cols_v = pick("cols").unwrap_or_default();
    let measure_v = pick("measure").unwrap_or_else(|| "id".to_string());
    let agg_v = pick("agg").unwrap_or_else(|| "count".to_string());
    // New (all optional): multiple measures, pinned filters, saved collapse state.
    let vals_v = pick("vals").unwrap_or_default();
    let filters_v = pick("filters").unwrap_or_default();
    let collapsed_v = pick("collapsed").unwrap_or_default();
    let config_json = serde_json::json!({
        "rows": rows_v.split(',').filter(|s| !s.is_empty()).collect::<Vec<_>>(),
        "cols": cols_v.split(',').filter(|s| !s.is_empty()).collect::<Vec<_>>(),
        "measure": measure_v,
        "agg": agg_v,
        "vals": vals_v,
        "filters": filters_v,
        "collapsed": collapsed_v,
    })
    .to_string();

    // Saved-views bar reflects the current config. measure+agg are always present
    // so the save form renders even for a bare pivot; the client keeps the
    // remaining cfg_* hidden inputs in step with live drag-drop state.
    let mut current_cfg = std::collections::BTreeMap::new();
    current_cfg.insert("measure".to_string(), measure_v.clone());
    current_cfg.insert("agg".to_string(), agg_v.clone());
    for (k, v) in [
        ("rows", &rows_v),
        ("cols", &cols_v),
        ("vals", &vals_v),
        ("filters", &filters_v),
        ("collapsed", &collapsed_v),
    ] {
        if !v.is_empty() {
            current_cfg.insert(k.to_string(), v.clone());
        }
    }
    let view_bar = vortex_framework::saved_views::render_view_bar(
        &db, &model_name, "pivot", &current_cfg, user.id, user.is_admin(),
    )
    .await;

    let sidebar_menu = build_sidebar_menu(&db, &user.roles, &model_name).await;

    // Shell built by token replacement (not format!) so the inline navbar JS
    // keeps its braces without escaping. Dynamic JSON goes into HTML-escaped
    // double-quoted data-* attributes.
    let html = PIVOT_SHELL
        .replace("__TITLE__", &html_escape(&model_display_name))
        .replace("__USER__", &html_escape(&user.username))
        .replace("__SIDEBAR__", &sidebar_menu)
        .replace("__LISTURL__", &html_escape(&list_view_url))
        .replace("__FIELDS__", &html_escape(&fields_json))
        .replace("__CONFIG__", &html_escape(&config_json))
        .replace("__MODEL__", &html_escape(&model_name));
    Html(html.replace("<!--VIEW_BAR-->", &view_bar)).into_response()
}

const PIVOT_SHELL: &str = r#"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)})()</script>
<style>[data-theme="corporate"] .theme-icon-sun{display:none !important}[data-theme="corporate"] .theme-icon-moon{display:inline-block !important}</style>
<title>__TITLE__ - Pivot</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<link href="/static/pivot.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script>
<style>
body { background: oklch(var(--b2)); color: oklch(var(--bc)); }
.top-navbar { background: oklch(var(--b1)); border-bottom: 1px solid oklch(var(--b3)); position: sticky; top: 0; z-index: 50; }
.sidebar { background: oklch(var(--b1)); border-right: 1px solid oklch(var(--b3)); }
.text-muted { color: oklch(var(--bc)/0.6); }
.user-badge { background: #8BC53F; color: #000; font-weight: 600; }
</style>
</head><body class="min-h-screen">
<nav class="top-navbar px-4 py-3 flex items-center justify-between">
  <div class="flex items-center gap-2">
    <button class="btn btn-ghost btn-sm btn-square md:hidden" onclick="var s=document.querySelector('.sidebar');s.classList.toggle('hidden');s.classList.toggle('md:block')"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button>
    <a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a>
  </div>
  <div class="flex items-center gap-2 md:gap-3">
    <a href="/home" class="text-base-content text-sm hover:underline hidden md:inline">Home</a>
    <a href="/settings" class="text-base-content text-sm hover:underline hidden md:inline">Settings</a>
    <button onclick="(function(){var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){e.classList.toggle('hidden')})})();" class="btn btn-ghost btn-circle btn-sm" title="Toggle theme"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button>
    <div class="user-badge px-3 py-1 rounded-full text-sm">@__USER__</div>
  </div>
</nav>
<div class="flex">
<aside class="sidebar w-64 min-h-screen p-4 hidden md:block"><ul class="menu mt-2">__SIDEBAR__</ul></aside>
<main class="flex-1 p-4 md:p-6 min-w-0">
<div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-4 gap-4">
  <div><h1 class="text-xl md:text-2xl font-bold">__TITLE__</h1><p class="text-muted">Pivot table — drag fields into Rows, Columns and Values</p></div>
  <div class="flex gap-2 flex-wrap">
    <div class="btn-group">
      <a href="__LISTURL__" class="btn btn-sm" title="List View"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg></a>
      <a href="/kanban/__MODEL__" class="btn btn-sm" title="Kanban View"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7"/></svg></a>
      <a href="/graph/__MODEL__" class="btn btn-sm" title="Graph View"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg></a>
      <a href="/calendar/__MODEL__" class="btn btn-sm" title="Calendar View"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg></a>
      <a href="/pivot/__MODEL__" class="btn btn-sm btn-active" title="Pivot View"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg></a>
    </div>
    <!--VIEW_BAR-->
    <button id="pv-export" class="btn btn-sm gap-1" title="Export to Excel (CSV)"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M7 10l5 5 5-5M12 15V3"/></svg>Excel</button>
    <a href="/__MODEL__/new" class="btn btn-sm" style="background:#8BC53F;border-color:#8BC53F;color:#000">+ New</a>
  </div>
</div>
<div class="pv-wrap">
  <div class="pv-main"><div id="pv-table-wrap"><div class="pv-hint">Loading…</div></div></div>
  <div class="pv-side">
    <h3>PivotTable Fields</h3>
    <div id="pv-fields"></div>
    <div class="pv-zones">
      <div class="pv-zone" id="pv-zone-filters" style="grid-column:1/-1"><div class="pv-zone-title">&#9660; Filters</div></div>
      <div class="pv-zone" id="pv-zone-rows"><div class="pv-zone-title">&#9636; Rows</div></div>
      <div class="pv-zone" id="pv-zone-cols"><div class="pv-zone-title">&#9638; Columns</div></div>
      <div class="pv-zone" id="pv-zone-values" style="grid-column:1/-1"><div class="pv-zone-title">&#931; Values</div></div>
    </div>
  </div>
</div>
<div id="pivot-root" data-model="__MODEL__" data-data-url="/pivot/__MODEL__/data" data-fields="__FIELDS__" data-config="__CONFIG__"></div>
<script src="/static/pivot.js?v=18"></script>
</main>
</div></body></html>"#;

/// GET /pivot/{model}/data — aggregated pivot matrix as JSON. Every field name
/// is allow-listed against the model registry; subtotals and grand totals are
/// computed by SQL ROLLUP (correct for every aggregate, at every level).
async fn generic_pivot_data(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let fail = |msg: &str| Json(serde_json::json!({"ok": false, "error": msg})).into_response();

    let model_row = match sqlx::query("SELECT id, table_name FROM ir_model WHERE name = $1 AND is_active = true")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
    {
        Ok(Some(r)) => r,
        _ => return fail("Unknown model"),
    };
    let model_id: uuid::Uuid = model_row.get("id");
    let table_name: String = model_row.get("table_name");
    if !validate_identifier(&table_name) {
        return fail("Invalid model");
    }

    let frows = sqlx::query("SELECT name, field_type, display_name, related_model FROM ir_model_field WHERE model_id = $1")
        .bind(model_id)
        .fetch_all(&db)
        .await
        .unwrap_or_default();
    let mut finfo: std::collections::HashMap<String, (String, String, Option<String>)> = std::collections::HashMap::new();
    for f in &frows {
        let n: String = f.get("name");
        finfo.insert(n, (f.get("field_type"), f.get("display_name"), f.try_get("related_model").ok().flatten()));
    }
    let has_active = finfo.contains_key("active");
    let is_field = |n: &str| -> bool { validate_identifier(n) && finfo.contains_key(n) };

    use base64::Engine as _;

    let parse_list = |key: &str| -> Vec<String> {
        params
            .get(key)
            .map(|s| s.as_str())
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .filter(|s| is_field(s))
            .collect()
    };
    let rows = parse_list("rows");
    let cols = parse_list("cols");

    let is_numeric = |n: &str| -> bool {
        finfo
            .get(n)
            .map(|(t, _, _)| matches!(t.as_str(), "integer" | "float" | "decimal" | "monetary" | "number"))
            .unwrap_or(false)
    };
    let label_of = |n: &str| -> String {
        finfo.get(n).map(|(_, d, _)| d.clone()).unwrap_or_else(|| n.to_string())
    };

    // The text (group-by) expression for a dimension, adding a LEFT JOIN to the
    // related table for a many2one so grouping/filtering is by human-readable
    // name rather than opaque id. `jidx` keeps join aliases unique across the
    // row, column and filter dimensions that share the FROM clause.
    fn dim_expr(
        field: &str,
        finfo: &std::collections::HashMap<String, (String, String, Option<String>)>,
        joins: &mut Vec<String>,
        jidx: &mut usize,
    ) -> String {
        match finfo.get(field) {
            Some((ftype, _, Some(rel))) if ftype == "many2one" => {
                let rel_table = rel.replace('.', "_");
                if validate_identifier(&rel_table) {
                    let ja = format!("j{}", *jidx);
                    *jidx += 1;
                    joins.push(format!("LEFT JOIN {} {} ON t.{} = {}.id", rel_table, ja, field, ja));
                    format!("{}.name", ja)
                } else {
                    format!("t.{}", field)
                }
            }
            _ => format!("t.{}", field),
        }
    }

    let mut joins: Vec<String> = Vec::new();
    let mut selects: Vec<String> = Vec::new();
    let mut row_gbs: Vec<String> = Vec::new();
    let mut col_gbs: Vec<String> = Vec::new();
    let mut jidx = 0usize;

    // Row/column grouping dimensions: emit the value, its GROUPING() flag, and
    // record the group-by expression for the ROLLUP.
    let mut build_group = |field: &str, alias: &str, gbs: &mut Vec<String>, joins: &mut Vec<String>, jidx: &mut usize, selects: &mut Vec<String>| {
        let gb = dim_expr(field, &finfo, joins, jidx);
        selects.push(format!("COALESCE(CAST({} AS TEXT), '(empty)') as {}", gb, alias));
        selects.push(format!("GROUPING({}) as g{}", gb, alias));
        gbs.push(gb);
    };
    for (i, field) in rows.iter().enumerate() {
        build_group(field, &format!("r{}", i), &mut row_gbs, &mut joins, &mut jidx, &mut selects);
    }
    for (i, field) in cols.iter().enumerate() {
        build_group(field, &format!("c{}", i), &mut col_gbs, &mut joins, &mut jidx, &mut selects);
    }

    // Measures (Values). `vals` is a comma list of `agg.field`; falls back to the
    // legacy single `measure`/`agg` params so old saved views/URLs keep working.
    // Each measure yields one aggregate column m0, m1, … in the SELECT.
    struct Measure {
        agg: String,
        field: String, // "id" == count of records
        label: String,
    }
    let mut measures: Vec<Measure> = Vec::new();
    let push_measure = |measures: &mut Vec<Measure>, agg: &str, field: &str| {
        let agg = if ["count", "sum", "avg", "min", "max"].contains(&agg) { agg } else { "count" };
        // Non-count aggregates need a numeric field; otherwise fall back to count.
        let (agg, field) = if field == "id" || !is_field(field) {
            ("count", "id")
        } else if agg != "count" && !is_numeric(field) {
            ("count", field)
        } else {
            (agg, field)
        };
        if measures.len() >= 12 {
            return;
        }
        let label = match (agg, field) {
            ("count", "id") => "Count".to_string(),
            ("count", f) => format!("Count of {}", label_of(f)),
            (a, f) => format!("{}{} of {}", a[..1].to_uppercase(), &a[1..], label_of(f)),
        };
        measures.push(Measure { agg: agg.to_string(), field: field.to_string(), label });
    };
    if let Some(vals) = params.get("vals").filter(|s| !s.is_empty()) {
        for tok in vals.split(',').filter(|s| !s.is_empty()) {
            let (agg, field) = tok.split_once('.').unwrap_or((tok, "id"));
            push_measure(&mut measures, agg, field);
        }
    }
    if measures.is_empty() {
        let agg = params.get("agg").map(|s| s.as_str()).unwrap_or("count");
        let field = params.get("measure").map(|s| s.as_str()).unwrap_or("id");
        push_measure(&mut measures, agg, field);
    }
    for (i, m) in measures.iter().enumerate() {
        let expr = match m.agg.as_str() {
            "sum" => format!("SUM(CAST(t.{} AS NUMERIC))", m.field),
            "avg" => format!("AVG(CAST(t.{} AS NUMERIC))", m.field),
            "min" => format!("MIN(CAST(t.{} AS NUMERIC))", m.field),
            "max" => format!("MAX(CAST(t.{} AS NUMERIC))", m.field),
            _ if m.field == "id" => "COUNT(*)".to_string(),
            _ => format!("COUNT(t.{})", m.field), // count of non-null values
        };
        selects.push(format!("CAST({} AS DOUBLE PRECISION) as m{}", expr, i));
    }

    // Pinned filters: `filters` is a comma list of `field.b64value`. The value is
    // matched against the same text/name expression used for grouping, bound as a
    // query parameter (never interpolated) — so arbitrary data is safe.
    let mut wheres: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if has_active {
        wheres.push("t.active = true".to_string());
    }
    if let Some(filters) = params.get("filters").filter(|s| !s.is_empty()) {
        for tok in filters.split(',').filter(|s| !s.is_empty()).take(20) {
            let Some((field, b64)) = tok.split_once('.') else { continue };
            if !is_field(field) {
                continue;
            }
            let value = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(b64)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64))
                .ok()
                .and_then(|b| String::from_utf8(b).ok());
            let Some(value) = value else { continue };
            let expr = dim_expr(field, &finfo, &mut joins, &mut jidx);
            binds.push(value);
            wheres.push(format!(
                "COALESCE(CAST({} AS TEXT), '(empty)') = ${}",
                expr,
                binds.len()
            ));
        }
    }

    let where_sql = if wheres.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", wheres.join(" AND "))
    };
    let group_sql = match (row_gbs.is_empty(), col_gbs.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!(" GROUP BY ROLLUP({})", row_gbs.join(", ")),
        (true, false) => format!(" GROUP BY ROLLUP({})", col_gbs.join(", ")),
        (false, false) => format!(" GROUP BY ROLLUP({}), ROLLUP({})", row_gbs.join(", "), col_gbs.join(", ")),
    };
    let query = format!(
        "SELECT {} FROM {} t {}{}{}",
        selects.join(", "),
        table_name,
        joins.join(" "),
        where_sql,
        group_sql
    );

    let mut q = sqlx::query(&query);
    for b in &binds {
        q = q.bind(b);
    }
    let results = match q.fetch_all(&db).await {
        Ok(r) => r,
        Err(e) => {
            error!("pivot data query failed: {e}");
            return fail("Could not compute pivot for these fields.");
        }
    };

    let mut cells: Vec<serde_json::Value> = Vec::new();
    for row in &results {
        let mut rpath: Vec<String> = Vec::new();
        for i in 0..rows.len() {
            let g: i32 = row.try_get::<i32, _>(format!("gr{}", i).as_str()).unwrap_or(1);
            if g == 0 {
                rpath.push(row.try_get::<String, _>(format!("r{}", i).as_str()).unwrap_or_default());
            } else {
                break;
            }
        }
        let mut cpath: Vec<String> = Vec::new();
        for i in 0..cols.len() {
            let g: i32 = row.try_get::<i32, _>(format!("gc{}", i).as_str()).unwrap_or(1);
            if g == 0 {
                cpath.push(row.try_get::<String, _>(format!("c{}", i).as_str()).unwrap_or_default());
            } else {
                break;
            }
        }
        let vs: Vec<serde_json::Value> = (0..measures.len())
            .map(|i| match row.try_get::<Option<f64>, _>(format!("m{}", i).as_str()) {
                Ok(Some(v)) => serde_json::json!(v),
                _ => serde_json::Value::Null,
            })
            .collect();
        cells.push(serde_json::json!({"r": rpath, "c": cpath, "vs": vs}));
    }

    let field_meta = |names: &[String]| -> Vec<serde_json::Value> {
        names
            .iter()
            .map(|n| serde_json::json!({"name": n, "label": label_of(n)}))
            .collect()
    };
    let measure_meta: Vec<serde_json::Value> = measures
        .iter()
        .map(|m| serde_json::json!({"agg": m.agg, "field": m.field, "label": m.label}))
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "measures": measure_meta,
        "rowFields": field_meta(&rows),
        "colFields": field_meta(&cols),
        "cells": cells,
    }))
    .into_response()
}

/// GET /pivot/{model}/values?field=X — distinct values of a field, for the pivot
/// Filters zone's value picker. Field name is allow-listed against the registry;
/// many2one fields resolve to the related record's name.
async fn generic_pivot_values(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let fail = |msg: &str| Json(serde_json::json!({"ok": false, "error": msg})).into_response();

    let model_row = match sqlx::query("SELECT id, table_name FROM ir_model WHERE name = $1 AND is_active = true")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
    {
        Ok(Some(r)) => r,
        _ => return fail("Unknown model"),
    };
    let model_id: uuid::Uuid = model_row.get("id");
    let table_name: String = model_row.get("table_name");
    if !validate_identifier(&table_name) {
        return fail("Invalid model");
    }
    let field = match params.get("field") {
        Some(f) if validate_identifier(f) => f.clone(),
        _ => return fail("Invalid field"),
    };

    let frow = sqlx::query(
        "SELECT field_type, related_model FROM ir_model_field WHERE model_id = $1 AND name = $2",
    )
    .bind(model_id)
    .bind(&field)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(frow) = frow else { return fail("Unknown field") };
    let ftype: String = frow.get("field_type");
    let related: Option<String> = frow.try_get("related_model").ok().flatten();

    let mut join = String::new();
    let expr = if ftype == "many2one" {
        match related.map(|r| r.replace('.', "_")).filter(|t| validate_identifier(t)) {
            Some(rel_table) => {
                join = format!(" LEFT JOIN {0} j0 ON t.{1} = j0.id", rel_table, field);
                "j0.name".to_string()
            }
            None => format!("t.{}", field),
        }
    } else {
        format!("t.{}", field)
    };
    let has_active = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM ir_model_field WHERE model_id = $1 AND name = 'active'",
    )
    .bind(model_id)
    .fetch_one(&db)
    .await
    .map(|n| n > 0)
    .unwrap_or(false);
    let where_sql = if has_active { " WHERE t.active = true" } else { "" };

    let query = format!(
        "SELECT DISTINCT COALESCE(CAST({0} AS TEXT), '(empty)') AS v FROM {1} t{2}{3} ORDER BY v LIMIT 300",
        expr, table_name, join, where_sql
    );
    let rows = match sqlx::query(&query).fetch_all(&db).await {
        Ok(r) => r,
        Err(e) => {
            error!("pivot values query failed: {e}");
            return fail("Could not read values for this field.");
        }
    };
    let values: Vec<String> = rows.iter().map(|r| r.get::<String, _>("v")).collect();
    Json(serde_json::json!({"ok": true, "values": values})).into_response()
}

// ============================================================================
// Saved Filters API
// ============================================================================

async fn get_filters(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
) -> Response {
    let filters = sqlx::query(
        r#"SELECT f.id, f.name, f.domain, f.context, f.is_default
           FROM ir_filters f
           JOIN ir_model m ON f.model_id = m.id
           WHERE m.name = $1 AND f.active = true AND (f.user_id IS NULL OR f.user_id = $2)
           ORDER BY f.name"#
    )
    .bind(&model_name)
    .bind(user.id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let result: Vec<serde_json::Value> = filters.iter().map(|f| {
        serde_json::json!({
            "id": f.get::<uuid::Uuid, _>("id").to_string(),
            "name": f.get::<String, _>("name"),
            "domain": f.get::<String, _>("domain"),
            "context": f.get::<String, _>("context"),
            "is_default": f.get::<bool, _>("is_default")
        })
    }).collect();

    Json(result).into_response()
}

#[derive(Debug, serde::Deserialize)]
struct SaveFilterRequest {
    name: String,
    domain: String,
    context: Option<String>,
    is_shared: Option<bool>,
}

async fn save_filter(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Form(form): Form<SaveFilterRequest>,
) -> Response {
    let model_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM ir_model WHERE name = $1")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(model_id) = model_id else {
        return (StatusCode::NOT_FOUND, "Model not found").into_response();
    };

    let user_id = if form.is_shared.unwrap_or(false) { None } else { Some(user.id) };

    let result = sqlx::query(
        "INSERT INTO ir_filters (name, model_id, user_id, domain, context) VALUES ($1, $2, $3, $4, $5) RETURNING id"
    )
    .bind(&form.name)
    .bind(model_id)
    .bind(user_id)
    .bind(&form.domain)
    .bind(form.context.as_deref().unwrap_or("{}"))
    .fetch_one(&db)
    .await;

    match result {
        Ok(row) => {
            let id: uuid::Uuid = row.get("id");
            Json(serde_json::json!({"id": id.to_string(), "success": true})).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ============================================================================
// Sequences API
// ============================================================================

async fn get_next_sequence(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(code): Path<String>,
) -> Response {
    let result: Result<String, _> = sqlx::query_scalar("SELECT next_sequence($1)")
        .bind(&code)
        .fetch_one(&db)
        .await;

    match result {
        Ok(seq) => Json(serde_json::json!({"sequence": seq})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("Sequence error: {}", e)).into_response(),
    }
}

// ============================================================================
// Attachments API
// ============================================================================

use axum::extract::Multipart;


async fn list_attachments(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
) -> Response {
    let attachments = sqlx::query(
        r#"SELECT id, name, mimetype, file_size, created_at, created_by
           FROM ir_attachment
           WHERE res_model = $1 AND res_id = $2
           ORDER BY created_at DESC"#
    )
    .bind(&model)
    .bind(record_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let result: Vec<serde_json::Value> = attachments.iter().map(|a| {
        serde_json::json!({
            "id": a.get::<uuid::Uuid, _>("id").to_string(),
            "name": a.get::<String, _>("name"),
            "mimetype": a.get::<Option<String>, _>("mimetype"),
            "file_size": a.get::<Option<i64>, _>("file_size"),
            "created_at": a.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        })
    }).collect();

    Json(result).into_response()
}

/// Storage key for a fresh upload: server-generated UUID + sanitized
/// extension from the client filename. Extensions outside
/// `[A-Za-z0-9]{1,10}` collapse to "bin" so client input can never
/// shape the key beyond a benign suffix.
fn new_store_key(prefix: &str, file_name: &str) -> String {
    let ext = std::path::Path::new(file_name)
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| e.len() <= 10 && e.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("bin");
    format!("{}{}.{}", prefix, uuid::Uuid::new_v4(), ext.to_ascii_lowercase())
}

async fn upload_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
    mut multipart: Multipart,
) -> Response {
    while let Ok(Some(field)) = multipart.next_field().await {
        let file_name = field.file_name().unwrap_or("unknown").to_string();
        let content_type = field.content_type().map(|s| s.to_string());

        // Read file data
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => return (StatusCode::BAD_REQUEST, format!("Failed to read file: {}", e)).into_response(),
        };

        let file_size = data.len() as i64;
        let store_fname = new_store_key("", &file_name);

        // Compute checksum
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let checksum = hex::encode(hasher.finalize());

        // Persist the blob under the tenant's namespace
        if let Err(e) = state
            .files
            .put(&db_ctx.db_name, &store_fname, &data, content_type.as_deref())
            .await
        {
            error!("attachment store failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to store file".to_string()).into_response();
        }

        // Insert record
        let result = sqlx::query(
            r#"INSERT INTO ir_attachment (name, res_model, res_id, store_fname, file_size, mimetype, checksum, created_by)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id"#
        )
        .bind(&file_name)
        .bind(&model)
        .bind(record_id)
        .bind(&store_fname)
        .bind(file_size)
        .bind(&content_type)
        .bind(&checksum)
        .bind(user.id)
        .fetch_one(&db)
        .await;

        match result {
            Ok(row) => {
                let id: uuid::Uuid = row.get("id");
                return Json(serde_json::json!({
                    "id": id.to_string(),
                    "name": file_name,
                    "size": file_size,
                    "success": true
                })).into_response();
            }
            Err(e) => {
                // Clean up blob on error so no orphan survives
                let _ = state.files.delete(&db_ctx.db_name, &store_fname).await;
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response();
            }
        }
    }

    (StatusCode::BAD_REQUEST, "No file provided").into_response()
}

async fn download_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let attachment = sqlx::query(
        "SELECT name, store_fname, mimetype FROM ir_attachment WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(att) = attachment else {
        return (StatusCode::NOT_FOUND, "Attachment not found").into_response();
    };

    let name: String = att.get("name");
    let store_fname: Option<String> = att.get("store_fname");
    let mimetype: Option<String> = att.get("mimetype");

    let Some(fname) = store_fname else {
        return (StatusCode::NOT_FOUND, "File not found in storage").into_response();
    };

    let data = match state.files.get(&db_ctx.db_name, &fname).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "File not found in storage").into_response(),
        Err(e) => {
            error!("attachment fetch failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Storage error").into_response();
        }
    };

    let content_type = mimetype.unwrap_or_else(|| "application/octet-stream".to_string());

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", name)),
        ],
        data,
    ).into_response()
}

async fn delete_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Get storage key first
    let attachment = sqlx::query("SELECT store_fname FROM ir_attachment WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    if let Some(att) = attachment {
        let store_fname: Option<String> = att.get("store_fname");
        if let Some(fname) = store_fname {
            let _ = state.files.delete(&db_ctx.db_name, &fname).await;
        }
    }

    let result = sqlx::query("DELETE FROM ir_attachment WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await;

    match result {
        Ok(_) => Json(serde_json::json!({"success": true})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ============================================================================
// Contacts Management Handlers
// ============================================================================

/// List all contacts with a proper table view
async fn contacts_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("contacts", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    let contacts = sqlx::query(
        "SELECT id, name, display_name, contact_type, email, phone, city, active FROM contacts ORDER BY name LIMIT 200"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows = String::new();
    for c in &contacts {
        let id: uuid::Uuid = c.get("id");
        let name: String = c.get("name");
        let display: Option<String> = c.get("display_name");
        let ctype: String = c.get("contact_type");
        let email: Option<String> = c.get("email");
        let phone: Option<String> = c.get("phone");
        let city: Option<String> = c.get("city");
        let active: bool = c.get("active");
        let status_badge = if active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else {
            r#"<span class="badge badge-warning badge-sm">Archived</span>"#
        };
        let type_badge = match ctype.as_str() {
            "customer" => r#"<span class="badge badge-info badge-sm">Customer</span>"#,
            "supplier" => r#"<span class="badge badge-secondary badge-sm">Supplier</span>"#,
            "both" => r#"<span class="badge badge-accent badge-sm">Both</span>"#,
            _ => r#"<span class="badge badge-ghost badge-sm">Other</span>"#,
        };
        rows.push_str(&format!(
            r#"<tr class="hover cursor-pointer" onclick="window.location='/contacts/{id}'">
            <td>{name}</td><td>{display}</td><td>{type_badge}</td>
            <td>{email}</td><td>{phone}</td><td>{city}</td><td>{status_badge}</td></tr>"#,
            id = id,
            name = html_escape(&name),
            display = html_escape(&display.unwrap_or_default()),
            type_badge = type_badge,
            email = html_escape(&email.unwrap_or_default()),
            phone = html_escape(&phone.unwrap_or_default()),
            city = html_escape(&city.unwrap_or_default()),
            status_badge = status_badge,
        ));
    }

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Contacts - Remicle</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6">
<div><h1 class="text-2xl font-bold">Contacts</h1><p class="text-base-content/60">Manage customers, suppliers, and stakeholders</p></div>
<a href="/contacts/new" class="btn btn-primary">+ New Contact</a>
</div>
<div class="card bg-base-100 shadow">
<div class="overflow-x-auto">
<table class="table table-sm">
<thead><tr><th>Name</th><th>Display Name</th><th>Type</th><th>Email</th><th>Phone</th><th>City</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody>
</table></div></div>
</main></div></body></html>"#)).into_response()
}

async fn contacts_new(State(state): State<Arc<AppState>>, Db(db): Db, Extension(_user): Extension<AuthUser>) -> Response {
    // Fetch countries for dropdown
    let countries = sqlx::query("SELECT id, name FROM countries WHERE active = true ORDER BY sequence, name")
        .fetch_all(&db).await.unwrap_or_default();

    let mut country_options = String::new();
    for co in &countries {
        let id: uuid::Uuid = co.get("id");
        let name: String = co.get("name");
        let escaped_name = name.replace("'", "\\'");
        country_options.push_str(&format!(r#"<div class="dropdown-item" data-id="{}" onclick="selectCountry('{}', '{}')">{}</div>"#, id, id, escaped_name, name));
    }

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>New Contact</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
<style>
.country-dropdown {{ position: relative; }}
.country-dropdown .dropdown-content {{ max-height: 300px; overflow-y: auto; width: 100%; }}
.country-dropdown .dropdown-item {{ padding: 8px 12px; cursor: pointer; }}
.country-dropdown .dropdown-item:hover {{ background: oklch(var(--b2)); }}
.state-dropdown {{ position: relative; }}
.state-dropdown .dropdown-content {{ max-height: 300px; overflow-y: auto; width: 100%; }}
.state-dropdown .dropdown-item {{ padding: 8px 12px; cursor: pointer; }}
.state-dropdown .dropdown-item:hover {{ background: oklch(var(--b2)); }}
</style>
</head><body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar-contact').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay-contact').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay-contact" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar-contact').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex"><aside id="sidebar-contact" class="w-64 bg-base-100 shadow-lg min-h-screen p-4 fixed lg:static top-0 left-0 z-40 h-full -translate-x-full lg:translate-x-0 transition-transform duration-200"><div class="text-xl font-bold mb-6"><span class="text-success">re</span><span class="opacity-60">micle</span></div><ul class="menu"><li><a href="/contacts">← Contacts</a></li></ul></aside><main class="flex-1 p-4 lg:p-6 min-w-0"><h1 class="text-2xl font-bold mb-6">New Contact</h1><form action="/contacts" method="POST" class="card bg-base-100 shadow p-6 max-w-3xl overflow-visible">
<h3 class="font-semibold text-lg mb-4">Basic Information</h3>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
<div class="form-control"><label class="label">Name *</label><input name="name" class="input input-bordered" required/></div>
<div class="form-control"><label class="label">Display Name</label><input name="display_name" class="input input-bordered"/></div>
<div class="form-control"><label class="label">Type</label><select name="contact_type" class="select select-bordered"><option value="customer">Customer</option><option value="vendor">Vendor</option><option value="employee">Employee</option><option value="other">Other</option></select></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-2"><input type="checkbox" name="is_company" class="checkbox"/><span>This is a Company</span></label></div>
</div>
<h3 class="font-semibold text-lg mt-6 mb-4">Contact Details</h3>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
<div class="form-control"><label class="label">Email</label><input name="email" type="email" class="input input-bordered"/></div>
<div class="form-control"><label class="label">Phone</label><input name="phone" class="input input-bordered"/></div>
<div class="form-control"><label class="label">Mobile</label><input name="mobile" class="input input-bordered"/></div>
</div>
<h3 class="font-semibold text-lg mt-6 mb-4">Address</h3>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
<div class="form-control col-span-2"><label class="label">Street</label><input name="street" class="input input-bordered"/></div>
<div class="form-control col-span-2"><label class="label">Street 2</label><input name="street2" class="input input-bordered"/></div>
<div class="form-control"><label class="label">City</label><input name="city" class="input input-bordered"/></div>
<div class="form-control"><label class="label">ZIP / Postal Code</label><input name="zip" class="input input-bordered"/></div>
<div class="form-control country-dropdown" style="position:relative">
  <label class="label">Country</label>
  <input type="text" id="country_search" class="input input-bordered" placeholder="Search country..." autocomplete="off" onclick="toggleCountryDropdown(true)" oninput="filterCountries()"/>
  <input type="hidden" name="country_id" id="country_id"/>
  <div id="country_list" style="display:none;position:absolute;top:100%;left:0;z-index:9999;max-height:300px;overflow-y:auto;width:100%;background:#1d232a;border:1px solid #374151;border-radius:8px;margin-top:4px;box-shadow:0 10px 25px rgba(0,0,0,0.5)">{}</div>
</div>
<div class="form-control state-dropdown" style="position:relative">
  <label class="label">State / Province</label>
  <input type="text" id="state_search" class="input input-bordered" placeholder="Select country first" autocomplete="off" onclick="toggleStateDropdown(true)" oninput="filterStates()" disabled/>
  <input type="hidden" name="state_id" id="state_id"/>
  <div id="state_list" style="display:none;position:absolute;top:100%;left:0;z-index:9999;max-height:300px;overflow-y:auto;width:100%;background:#1d232a;border:1px solid #374151;border-radius:8px;margin-top:4px;box-shadow:0 10px 25px rgba(0,0,0,0.5)"></div>
</div>
</div>
<div class="flex gap-2 mt-6"><a href="/contacts" class="btn btn-ghost">Cancel</a><button class="btn btn-primary">Create Contact</button></div>
</form></main></div>
<script>
let allCountries = [];
let allStates = [];

document.addEventListener('DOMContentLoaded', function() {{
    // Parse countries from data attribute
    const countryList = document.getElementById('country_list');
    allCountries = Array.from(countryList.querySelectorAll('.dropdown-item')).map(el => ({{
        id: el.dataset.id,
        name: el.textContent
    }}));
}});

function toggleCountryDropdown(show) {{
    const list = document.getElementById('country_list');
    if (show) {{
        list.style.display = 'block';
        filterCountries();
    }} else {{
        setTimeout(() => list.style.display = 'none', 150);
    }}
}}

function filterCountries() {{
    const search = document.getElementById('country_search').value.toLowerCase();
    const list = document.getElementById('country_list');
    const items = list.querySelectorAll('.dropdown-item');
    items.forEach(item => {{
        const match = item.textContent.toLowerCase().includes(search);
        item.style.display = match ? 'block' : 'none';
    }});
}}

function selectCountry(id, name) {{
    document.getElementById('country_id').value = id;
    document.getElementById('country_search').value = name;
    document.getElementById('country_list').style.display = 'none';
    loadStates(id);
}}

async function loadStates(countryId) {{
    const stateSearch = document.getElementById('state_search');
    const stateList = document.getElementById('state_list');
    document.getElementById('state_id').value = '';
    stateSearch.value = '';

    if (!countryId) {{
        stateSearch.placeholder = 'Select country first';
        stateSearch.disabled = true;
        stateList.innerHTML = '';
        allStates = [];
        return;
    }}

    stateSearch.placeholder = 'Loading...';
    stateSearch.disabled = true;

    try {{
        const res = await fetch(`/api/states/${{countryId}}`);
        const states = await res.json();
        allStates = states;

        if (states.length === 0) {{
            stateSearch.placeholder = 'No states available';
            stateList.innerHTML = '';
        }} else {{
            stateSearch.placeholder = 'Search state...';
            stateSearch.disabled = false;
            stateList.innerHTML = states.map(s =>
                `<div class="dropdown-item" data-id="${{s.id}}" onclick="selectState('${{s.id}}', '${{s.name.replace(/'/g, "\\'")}}')">${{s.name}}</div>`
            ).join('');
        }}
    }} catch (e) {{
        stateSearch.placeholder = 'Error loading states';
        stateList.innerHTML = '';
    }}
}}

function toggleStateDropdown(show) {{
    const list = document.getElementById('state_list');
    if (show && allStates.length > 0) {{
        list.style.display = 'block';
        filterStates();
    }} else {{
        setTimeout(() => list.style.display = 'none', 150);
    }}
}}

function filterStates() {{
    const search = document.getElementById('state_search').value.toLowerCase();
    const list = document.getElementById('state_list');
    const items = list.querySelectorAll('.dropdown-item');
    items.forEach(item => {{
        const match = item.textContent.toLowerCase().includes(search);
        item.style.display = match ? 'block' : 'none';
    }});
}}

function selectState(id, name) {{
    document.getElementById('state_id').value = id;
    document.getElementById('state_search').value = name;
    document.getElementById('state_list').style.display = 'none';
}}

// Close dropdowns when clicking outside
document.addEventListener('click', function(e) {{
    if (!e.target.closest('.country-dropdown')) {{
        document.getElementById('country_list').style.display = 'none';
    }}
    if (!e.target.closest('.state-dropdown')) {{
        document.getElementById('state_list').style.display = 'none';
    }}
}});
</script>
</body></html>"#, country_options)).into_response()
}

#[derive(serde::Deserialize)]
struct ContactForm {
    name: String,
    display_name: Option<String>,
    contact_type: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    mobile: Option<String>,
    street: Option<String>,
    street2: Option<String>,
    city: Option<String>,
    zip: Option<String>,
    country_id: Option<String>,
    state_id: Option<String>,
    is_company: Option<String>,
}

async fn contacts_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<ContactForm>,
) -> Response {
    let id = uuid::Uuid::now_v7();
    let ctype = form.contact_type.as_deref().unwrap_or("customer");
    let is_company = form.is_company.is_some();
    let country_id: Option<uuid::Uuid> = form.country_id.as_ref().and_then(|s| s.parse().ok());
    let state_id: Option<uuid::Uuid> = form.state_id.as_ref().and_then(|s| s.parse().ok());

    // Get user's company_id
    let company_id: uuid::Uuid = match sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&db)
        .await
    {
        Ok(cid) => cid,
        Err(e) => {
            error!("Failed to get user company: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Html("Error: Could not determine company")).into_response();
        }
    };

    if let Err(e) = sqlx::query(
        "INSERT INTO contacts (id, company_id, name, display_name, contact_type, email, phone, mobile, street, street2, city, zip, country_id, state_id, is_company, active, created_at, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,true,NOW(),$16)"
    )
    .bind(id).bind(company_id).bind(&form.name).bind(&form.display_name).bind(ctype)
    .bind(&form.email).bind(&form.phone).bind(&form.mobile)
    .bind(&form.street).bind(&form.street2).bind(&form.city).bind(&form.zip)
    .bind(country_id).bind(state_id).bind(is_company).bind(user.id)
    .execute(&db).await {
        error!("Failed to create contact: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error creating contact: {}", e))).into_response();
    }

    // Log creation to chatter
    let _ = sqlx::query(
        "INSERT INTO chatter_messages (res_model, res_id, message_type, body, author_id, company_id, created_by)
         VALUES ('contacts', $1, 'system', 'Contact created', $2, $3, $2)"
    )
    .bind(id)
    .bind(user.id)
    .bind(company_id)
    .execute(&db)
    .await;

    Redirect::to(&format!("/contacts/{}", id)).into_response()
}

async fn contacts_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let c = match sqlx::query("SELECT * FROM contacts WHERE id = $1").bind(id).fetch_optional(&db).await {
        Ok(Some(r)) => r,
        _ => return (StatusCode::NOT_FOUND, Html("Not found")).into_response(),
    };

    let name: String = c.get("name");
    let display_name: Option<String> = c.get("display_name");
    let ctype: String = c.get("contact_type");
    let email: Option<String> = c.get("email");
    let phone: Option<String> = c.get("phone");
    let mobile: Option<String> = c.get("mobile");
    let street: Option<String> = c.get("street");
    let street2: Option<String> = c.get("street2");
    let city: Option<String> = c.get("city");
    let zip: Option<String> = c.get("zip");
    let country_id: Option<uuid::Uuid> = c.get("country_id");
    let state_id: Option<uuid::Uuid> = c.get("state_id");
    let is_company: bool = c.get("is_company");
    let record_state: String = c.try_get("record_state").unwrap_or("draft".to_string());

    // Fetch countries
    let countries = sqlx::query("SELECT id, name FROM countries WHERE active = true ORDER BY sequence, name")
        .fetch_all(&db).await.unwrap_or_default();

    let mut country_options = String::new();
    let mut selected_country_name = String::new();
    for co in &countries {
        let cid: uuid::Uuid = co.get("id");
        let cname: String = co.get("name");
        let escaped_name = cname.replace("'", "\\'");
        if Some(cid) == country_id {
            selected_country_name = cname.clone();
        }
        country_options.push_str(&format!(r#"<div class="dropdown-item" data-id="{}" onclick="selectCountry('{}', '{}')">{}</div>"#, cid, cid, escaped_name, cname));
    }

    // Fetch states for the selected country
    let mut state_options = String::new();
    let mut selected_state_name = String::new();
    if let Some(cid) = country_id {
        let states = sqlx::query("SELECT id, name FROM states WHERE country_id = $1 AND active = true ORDER BY name")
            .bind(cid).fetch_all(&db).await.unwrap_or_default();
        for s in &states {
            let sid: uuid::Uuid = s.get("id");
            let sname: String = s.get("name");
            let escaped_name = sname.replace("'", "\\'");
            if Some(sid) == state_id {
                selected_state_name = sname.clone();
            }
            state_options.push_str(&format!(r#"<div class="dropdown-item" data-id="{}" onclick="selectState('{}', '{}')">{}</div>"#, sid, sid, escaped_name, sname));
        }
    }

    let type_sel = |t: &str| if ctype == t { " selected" } else { "" };

    let has_states = !state_options.is_empty();
    let state_placeholder = if country_id.is_some() {
        if has_states { "Search state..." } else { "No states available" }
    } else {
        "Select country first"
    };

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Edit Contact</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script><script src="/static/vendor/htmx.min.js"></script>
<style>
.country-dropdown {{ position: relative; }}
.country-dropdown .dropdown-content {{ max-height: 300px; overflow-y: auto; width: 100%; }}
.country-dropdown .dropdown-item {{ padding: 8px 12px; cursor: pointer; }}
.country-dropdown .dropdown-item:hover {{ background: oklch(var(--b2)); }}
.state-dropdown {{ position: relative; }}
.state-dropdown .dropdown-content {{ max-height: 300px; overflow-y: auto; width: 100%; }}
.state-dropdown .dropdown-item {{ padding: 8px 12px; cursor: pointer; }}
.state-dropdown .dropdown-item:hover {{ background: oklch(var(--b2)); }}
</style>
</head><body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar-contact').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay-contact').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay-contact" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar-contact').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex"><aside id="sidebar-contact" class="w-64 bg-base-100 shadow-lg min-h-screen p-4 fixed lg:static top-0 left-0 z-40 h-full -translate-x-full lg:translate-x-0 transition-transform duration-200"><div class="text-xl font-bold mb-6"><span class="text-success">re</span><span class="opacity-60">micle</span></div><ul class="menu"><li><a href="/contacts">← Contacts</a></li></ul></aside><main class="flex-1 p-4 lg:p-6 min-w-0">
<!-- State Bar -->
<div class="card bg-base-100 shadow mb-6">
  <div class="card-body py-3">
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-2">
        <span class="text-sm font-medium text-base-content/60">Status:</span>
        <ul class="steps steps-horizontal">
          <li class="step {}" data-content="1">Draft</li>
          <li class="step {}" data-content="2">Approved</li>
        </ul>
      </div>
      <div class="flex gap-2">
        {}
      </div>
    </div>
  </div>
</div>
<div class="flex justify-between mb-6"><h1 class="text-2xl font-bold">Edit Contact</h1><form action="/contacts/{}/delete" method="POST" onsubmit="return confirm('Delete this contact?')"><button class="btn btn-error btn-outline btn-sm">Delete</button></form></div>
<div class="grid grid-cols-1 xl:grid-cols-3 gap-6">
<form action="/contacts/{}" method="POST" class="card bg-base-100 shadow p-6 xl:col-span-2 overflow-visible">
{}
<h3 class="font-semibold text-lg mb-4">Basic Information</h3>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
<div class="form-control"><label class="label">Name *</label><input name="name" value="{}" class="input input-bordered" {} required/></div>
<div class="form-control"><label class="label">Display Name</label><input name="display_name" value="{}" class="input input-bordered" {}/></div>
<div class="form-control"><label class="label">Type</label><select name="contact_type" class="select select-bordered" {}><option value="customer"{}>Customer</option><option value="vendor"{}>Vendor</option><option value="employee"{}>Employee</option><option value="other"{}>Other</option></select></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-2"><input type="checkbox" name="is_company" class="checkbox" {} {}/><span>This is a Company</span></label></div>
</div>
<h3 class="font-semibold text-lg mt-6 mb-4">Contact Details</h3>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
<div class="form-control"><label class="label">Email</label><input name="email" type="email" value="{}" class="input input-bordered" {}/></div>
<div class="form-control"><label class="label">Phone</label><input name="phone" value="{}" class="input input-bordered" {}/></div>
<div class="form-control"><label class="label">Mobile</label><input name="mobile" value="{}" class="input input-bordered" {}/></div>
</div>
<h3 class="font-semibold text-lg mt-6 mb-4">Address</h3>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
<div class="form-control col-span-2"><label class="label">Street</label><input name="street" value="{}" class="input input-bordered" {}/></div>
<div class="form-control col-span-2"><label class="label">Street 2</label><input name="street2" value="{}" class="input input-bordered" {}/></div>
<div class="form-control"><label class="label">City</label><input name="city" value="{}" class="input input-bordered" {}/></div>
<div class="form-control"><label class="label">ZIP / Postal Code</label><input name="zip" value="{}" class="input input-bordered" {}/></div>
<div class="form-control country-dropdown" style="position:relative">
  <label class="label">Country</label>
  <input type="text" id="country_search" class="input input-bordered" placeholder="Search country..." value="{}" autocomplete="off" onclick="toggleCountryDropdown(true)" oninput="filterCountries()" {}/>
  <input type="hidden" name="country_id" id="country_id" value="{}"/>
  <div id="country_list" style="display:none;position:absolute;top:100%;left:0;z-index:9999;max-height:300px;overflow-y:auto;width:100%;background:#1d232a;border:1px solid #374151;border-radius:8px;margin-top:4px;box-shadow:0 10px 25px rgba(0,0,0,0.5)">{}</div>
</div>
<div class="form-control state-dropdown" style="position:relative">
  <label class="label">State / Province</label>
  <input type="text" id="state_search" class="input input-bordered" placeholder="{}" value="{}" autocomplete="off" onclick="toggleStateDropdown(true)" oninput="filterStates()" {}/>
  <input type="hidden" name="state_id" id="state_id" value="{}"/>
  <div id="state_list" style="display:none;position:absolute;top:100%;left:0;z-index:9999;max-height:300px;overflow-y:auto;width:100%;background:#1d232a;border:1px solid #374151;border-radius:8px;margin-top:4px;box-shadow:0 10px 25px rgba(0,0,0,0.5)">{}</div>
</div>
</div>
<div class="flex gap-2 mt-6"><a href="/contacts" class="btn btn-ghost">Cancel</a>{}</div>
</form>
<div class="xl:col-span-1">
  <div id="activity-stream" class="sticky top-4">
    <div class="card bg-base-100 shadow">
      <div class="card-body">
        <div class="flex items-center justify-center py-8">
          <span class="loading loading-spinner loading-md"></span>
        </div>
      </div>
    </div>
  </div>
</div>
</div></main></div>
<script>
let allCountries = [];
let allStates = [];

document.addEventListener('DOMContentLoaded', function() {{
    const countryList = document.getElementById('country_list');
    allCountries = Array.from(countryList.querySelectorAll('.dropdown-item')).map(el => ({{
        id: el.dataset.id,
        name: el.textContent
    }}));
    const stateList = document.getElementById('state_list');
    allStates = Array.from(stateList.querySelectorAll('.dropdown-item')).map(el => ({{
        id: el.dataset.id,
        name: el.textContent
    }}));
}});

function toggleCountryDropdown(show) {{
    const list = document.getElementById('country_list');
    if (show) {{
        list.style.display = 'block';
        filterCountries();
    }} else {{
        setTimeout(() => list.style.display = 'none', 150);
    }}
}}

function filterCountries() {{
    const search = document.getElementById('country_search').value.toLowerCase();
    const list = document.getElementById('country_list');
    const items = list.querySelectorAll('.dropdown-item');
    items.forEach(item => {{
        const match = item.textContent.toLowerCase().includes(search);
        item.style.display = match ? 'block' : 'none';
    }});
}}

function selectCountry(id, name) {{
    document.getElementById('country_id').value = id;
    document.getElementById('country_search').value = name;
    document.getElementById('country_list').style.display = 'none';
    loadStates(id);
}}

async function loadStates(countryId) {{
    const stateSearch = document.getElementById('state_search');
    const stateList = document.getElementById('state_list');
    document.getElementById('state_id').value = '';
    stateSearch.value = '';

    if (!countryId) {{
        stateSearch.placeholder = 'Select country first';
        stateSearch.disabled = true;
        stateList.innerHTML = '';
        allStates = [];
        return;
    }}

    stateSearch.placeholder = 'Loading...';
    stateSearch.disabled = true;

    try {{
        const res = await fetch(`/api/states/${{countryId}}`);
        const states = await res.json();
        allStates = states;

        if (states.length === 0) {{
            stateSearch.placeholder = 'No states available';
            stateList.innerHTML = '';
        }} else {{
            stateSearch.placeholder = 'Search state...';
            stateSearch.disabled = false;
            stateList.innerHTML = states.map(s =>
                `<div class="dropdown-item" data-id="${{s.id}}" onclick="selectState('${{s.id}}', '${{s.name.replace(/'/g, "\\'")}}')">${{s.name}}</div>`
            ).join('');
        }}
    }} catch (e) {{
        stateSearch.placeholder = 'Error loading states';
        stateList.innerHTML = '';
    }}
}}

function toggleStateDropdown(show) {{
    const list = document.getElementById('state_list');
    if (show && allStates.length > 0) {{
        list.style.display = 'block';
        filterStates();
    }} else {{
        setTimeout(() => list.style.display = 'none', 150);
    }}
}}

function filterStates() {{
    const search = document.getElementById('state_search').value.toLowerCase();
    const list = document.getElementById('state_list');
    const items = list.querySelectorAll('.dropdown-item');
    items.forEach(item => {{
        const match = item.textContent.toLowerCase().includes(search);
        item.style.display = match ? 'block' : 'none';
    }});
}}

function selectState(id, name) {{
    document.getElementById('state_id').value = id;
    document.getElementById('state_search').value = name;
    document.getElementById('state_list').style.display = 'none';
}}

document.addEventListener('click', function(e) {{
    if (!e.target.closest('.country-dropdown')) {{
        document.getElementById('country_list').style.display = 'none';
    }}
    if (!e.target.closest('.state-dropdown')) {{
        document.getElementById('state_list').style.display = 'none';
    }}
}});

// Load chatter component
fetch('/partials/chatter/contacts/{}')
    .then(r => r.text())
    .then(html => {{
        const panel = document.getElementById('activity-stream');
        panel.innerHTML = html;
        htmx.process(panel);
    }})
    .catch(e => {{
        document.getElementById('activity-stream').innerHTML = '<div class="card bg-base-100 shadow"><div class="card-body text-center text-base-content/60">Activity Stream unavailable</div></div>';
    }});
</script>
</body></html>"#,
        // State bar: draft step class, approved step class, action button
        if record_state == "draft" || record_state == "approved" { "step-primary" } else { "" },
        if record_state == "approved" { "step-primary" } else { "" },
        if record_state == "draft" {
            format!(r#"<form action="/contacts/{}/approve" method="POST" class="inline"><button class="btn btn-success btn-sm">Approve</button></form>"#, id)
        } else {
            format!(r#"<span class="badge badge-success gap-1"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Approved</span><form action="/contacts/{}/set-draft" method="POST" class="inline ml-2"><button class="btn btn-ghost btn-sm">Set to Draft</button></form>"#, id)
        },
        id,  // delete form action
        id,  // update form action
        // Locked banner when approved
        if record_state == "approved" {
            r#"<div class="alert alert-info mb-4"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg><span>This record is approved and read-only. Set to Draft to edit.</span></div>"#
        } else { "" },
        name, if record_state == "approved" { "disabled" } else { "" },
        display_name.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        if record_state == "approved" { "disabled" } else { "" },
        type_sel("customer"), type_sel("vendor"), type_sel("employee"), type_sel("other"),
        if record_state == "approved" { "disabled" } else { "" },
        if is_company { "checked" } else { "" },
        email.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        phone.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        mobile.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        street.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        street2.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        city.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        zip.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        selected_country_name, if record_state == "approved" { "disabled" } else { "" },
        country_id.map(|id| id.to_string()).unwrap_or_default(), country_options,
        state_placeholder, selected_state_name,
        if record_state == "approved" { "disabled" } else if has_states { "" } else { "disabled" },
        state_id.map(|id| id.to_string()).unwrap_or_default(), state_options,
        // Save button - only show when draft
        if record_state == "draft" {
            r#"<button class="btn btn-primary">Save Changes</button>"#
        } else {
            r#"<button class="btn btn-primary btn-disabled" disabled>Save Changes</button>"#
        },
        id  // for chatter fetch URL
    )).into_response()
}

async fn contacts_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<ContactForm>,
) -> Response {
    // Fetch old values for change tracking
    let old = sqlx::query("SELECT * FROM contacts WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let ctype = form.contact_type.as_deref().unwrap_or("customer");
    let is_company = form.is_company.is_some();
    let country_id: Option<uuid::Uuid> = form.country_id.as_ref().and_then(|s| s.parse().ok());
    let state_id: Option<uuid::Uuid> = form.state_id.as_ref().and_then(|s| s.parse().ok());

    let _ = sqlx::query(
        "UPDATE contacts SET name=$1, display_name=$2, contact_type=$3, email=$4, phone=$5, mobile=$6, street=$7, street2=$8, city=$9, zip=$10, country_id=$11, state_id=$12, is_company=$13, updated_at=NOW(), updated_by=$14 WHERE id=$15"
    )
    .bind(&form.name).bind(&form.display_name).bind(ctype)
    .bind(&form.email).bind(&form.phone).bind(&form.mobile)
    .bind(&form.street).bind(&form.street2).bind(&form.city).bind(&form.zip)
    .bind(country_id).bind(state_id).bind(is_company).bind(user.id).bind(id)
    .execute(&db).await;

    // Track changes
    if let Some(old) = old {
        let mut changes: Vec<String> = Vec::new();
        let company_id: uuid::Uuid = old.get("company_id");

        // Compare fields
        let old_name: String = old.get("name");
        if old_name != form.name {
            changes.push(format!("<b>Name</b> changed from '{}' to '{}'", old_name, form.name));
        }

        let old_display_name: Option<String> = old.get("display_name");
        if old_display_name != form.display_name {
            changes.push(format!("<b>Display Name</b> changed from '{}' to '{}'",
                old_display_name.as_deref().unwrap_or("-"),
                form.display_name.as_deref().unwrap_or("-")));
        }

        let old_type: String = old.get("contact_type");
        if old_type != ctype {
            changes.push(format!("<b>Type</b> changed from '{}' to '{}'", old_type, ctype));
        }

        let old_email: Option<String> = old.get("email");
        if old_email != form.email {
            changes.push(format!("<b>Email</b> changed from '{}' to '{}'",
                old_email.as_deref().unwrap_or("-"),
                form.email.as_deref().unwrap_or("-")));
        }

        let old_phone: Option<String> = old.get("phone");
        if old_phone != form.phone {
            changes.push(format!("<b>Phone</b> changed from '{}' to '{}'",
                old_phone.as_deref().unwrap_or("-"),
                form.phone.as_deref().unwrap_or("-")));
        }

        let old_mobile: Option<String> = old.get("mobile");
        if old_mobile != form.mobile {
            changes.push(format!("<b>Mobile</b> changed from '{}' to '{}'",
                old_mobile.as_deref().unwrap_or("-"),
                form.mobile.as_deref().unwrap_or("-")));
        }

        let old_street: Option<String> = old.get("street");
        if old_street != form.street {
            changes.push(format!("<b>Street</b> changed from '{}' to '{}'",
                old_street.as_deref().unwrap_or("-"),
                form.street.as_deref().unwrap_or("-")));
        }

        let old_city: Option<String> = old.get("city");
        if old_city != form.city {
            changes.push(format!("<b>City</b> changed from '{}' to '{}'",
                old_city.as_deref().unwrap_or("-"),
                form.city.as_deref().unwrap_or("-")));
        }

        let old_is_company: bool = old.get("is_company");
        if old_is_company != is_company {
            changes.push(format!("<b>Is Company</b> changed from '{}' to '{}'",
                if old_is_company { "Yes" } else { "No" },
                if is_company { "Yes" } else { "No" }));
        }

        // Log changes to chatter if any
        if !changes.is_empty() {
            let body = changes.join("<br>");
            let _ = sqlx::query(
                "INSERT INTO chatter_messages (res_model, res_id, message_type, body, author_id, company_id, created_by)
                 VALUES ('contacts', $1, 'system', $2, $3, $4, $3)"
            )
            .bind(id)
            .bind(&body)
            .bind(user.id)
            .bind(company_id)
            .execute(&db)
            .await;
        }
    }

    Redirect::to(&format!("/contacts/{}", id)).into_response()
}

async fn contacts_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let _ = sqlx::query("UPDATE contacts SET active=false, updated_at=NOW(), updated_by=$1 WHERE id=$2")
        .bind(user.id).bind(id).execute(&db).await;
    Redirect::to("/contacts").into_response()
}

async fn contacts_approve(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Get company_id for chatter message
    let contact = sqlx::query("SELECT company_id FROM contacts WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let _ = sqlx::query("UPDATE contacts SET record_state='approved', updated_at=NOW(), updated_by=$1 WHERE id=$2")
        .bind(user.id).bind(id).execute(&db).await;

    // Log state change to chatter
    if let Some(contact) = contact {
        let company_id: uuid::Uuid = contact.get("company_id");
        let _ = sqlx::query(
            "INSERT INTO chatter_messages (res_model, res_id, message_type, body, author_id, company_id, created_by)
             VALUES ('contacts', $1, 'system', '<b>Status</b> changed from <span class=\"badge badge-warning badge-sm\">Draft</span> to <span class=\"badge badge-success badge-sm\">Approved</span>', $2, $3, $2)"
        )
        .bind(id)
        .bind(user.id)
        .bind(company_id)
        .execute(&db)
        .await;
    }

    Redirect::to(&format!("/contacts/{}", id)).into_response()
}

async fn contacts_set_draft(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Get company_id for chatter message
    let contact = sqlx::query("SELECT company_id FROM contacts WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let _ = sqlx::query("UPDATE contacts SET record_state='draft', updated_at=NOW(), updated_by=$1 WHERE id=$2")
        .bind(user.id).bind(id).execute(&db).await;

    // Log state change to chatter
    if let Some(contact) = contact {
        let company_id: uuid::Uuid = contact.get("company_id");
        let _ = sqlx::query(
            "INSERT INTO chatter_messages (res_model, res_id, message_type, body, author_id, company_id, created_by)
             VALUES ('contacts', $1, 'system', '<b>Status</b> changed from <span class=\"badge badge-success badge-sm\">Approved</span> to <span class=\"badge badge-warning badge-sm\">Draft</span>', $2, $3, $2)"
        )
        .bind(id)
        .bind(user.id)
        .bind(company_id)
        .execute(&db)
        .await;
    }

    Redirect::to(&format!("/contacts/{}", id)).into_response()
}

// =============================================================================
// Chatter
// =============================================================================

/// Chatter partial for any model
async fn chatter_partial(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
) -> Response {
    // Fetch messages for this record
    let messages = sqlx::query(
        "SELECT m.id, m.body, m.message_type, m.is_internal, m.created_at, u.username as author_name
         FROM chatter_messages m
         LEFT JOIN users u ON m.author_id = u.id
         WHERE m.res_model = $1 AND m.res_id = $2 AND m.active = true
         ORDER BY m.created_at DESC
         LIMIT 50"
    )
    .bind(&model)
    .bind(record_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Fetch activities for this record
    let activities = sqlx::query(
        "SELECT a.id, a.summary, a.due_date, a.state, t.name as type_name, t.icon, u.username as assigned_to
         FROM chatter_activities a
         LEFT JOIN chatter_activity_types t ON a.activity_type_id = t.id
         LEFT JOIN users u ON a.assigned_to_id = u.id
         WHERE a.res_model = $1 AND a.res_id = $2 AND a.active = true
         ORDER BY a.due_date ASC
         LIMIT 20"
    )
    .bind(&model)
    .bind(record_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Fetch activity types for dropdown
    let activity_types = sqlx::query(
        "SELECT id, name FROM chatter_activity_types WHERE active = true ORDER BY sequence, name"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Fetch attachments for this record
    let attachments = sqlx::query(
        "SELECT a.id, a.name, a.file_size, a.mime_type, a.created_at, a.is_secure, a.created_by, u.username as uploaded_by
         FROM chatter_attachments a
         LEFT JOIN users u ON a.created_by = u.id
         WHERE a.res_model = $1 AND a.res_id = $2 AND a.active = true
         ORDER BY a.created_at DESC
         LIMIT 50"
    )
    .bind(&model)
    .bind(record_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Get user's company_id for fetching assignable users
    let company_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    // Fetch users from same company for assignment dropdown
    let assignable_users = if let Some(cid) = company_id {
        sqlx::query("SELECT id, username FROM users WHERE company_id = $1 AND active = true ORDER BY username")
            .bind(cid)
            .fetch_all(&db)
            .await
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Build messages HTML
    let mut messages_html = String::new();
    for msg in &messages {
        let body: String = msg.get("body");
        let author: Option<String> = msg.get("author_name");
        let created_at: chrono::DateTime<chrono::Utc> = msg.get("created_at");
        let msg_type: String = msg.get("message_type");
        let is_internal: bool = msg.get("is_internal");

        let badge = if is_internal {
            r#"<span class="badge badge-ghost badge-sm">Internal</span>"#
        } else if msg_type == "system" {
            r#"<span class="badge badge-info badge-sm">System</span>"#
        } else {
            ""
        };

        messages_html.push_str(&format!(
            r#"<div class="chat chat-start">
                <div class="chat-header">{} {} <time class="text-xs opacity-50">{}</time></div>
                <div class="chat-bubble chat-bubble-ghost">{}</div>
            </div>"#,
            author.unwrap_or_else(|| "System".to_string()),
            badge,
            created_at.format("%Y-%m-%d %H:%M"),
            body
        ));
    }

    if messages_html.is_empty() {
        messages_html = r#"<div class="text-center text-base-content/50 py-4">No messages yet</div>"#.to_string();
    }

    // Build activities HTML
    let mut activities_html = String::new();
    for act in &activities {
        let act_id: uuid::Uuid = act.get("id");
        let summary: Option<String> = act.get("summary");
        let due_date: chrono::NaiveDate = act.get("due_date");
        let state: String = act.get("state");
        let type_name: Option<String> = act.get("type_name");
        let assigned_to: Option<String> = act.get("assigned_to");

        let (state_badge, action_btn) = match state.as_str() {
            "completed" => (
                r#"<span class="badge badge-success badge-sm">Done</span>"#.to_string(),
                String::new()
            ),
            "overdue" | "pending" | _ => (
                if state == "overdue" {
                    r#"<span class="badge badge-error badge-sm">Overdue</span>"#.to_string()
                } else {
                    r#"<span class="badge badge-warning badge-sm">Pending</span>"#.to_string()
                },
                format!(
                    "<div class=\"join\">\
                        <button class=\"btn btn-success btn-xs join-item\" hx-post=\"/api/chatter/{}/{}/activities/{}/complete\" hx-target=\"#activity-stream\" hx-swap=\"innerHTML\" title=\"Mark as Done\">Done</button>\
                        <button class=\"btn btn-ghost btn-xs join-item\" hx-post=\"/api/chatter/{}/{}/activities/{}/complete-and-schedule\" hx-target=\"#activity-stream\" hx-swap=\"innerHTML\" title=\"Done & Schedule Next\">+Next</button>\
                    </div>",
                    model, record_id, act_id, model, record_id, act_id
                )
            ),
        };

        activities_html.push_str(&format!(
            r#"<div class="flex items-center gap-2 p-2 rounded hover:bg-base-200">
                <div class="flex-1">
                    <div class="font-medium">{}</div>
                    <div class="text-xs text-base-content/60">{} · {}</div>
                </div>
                {}{}
            </div>"#,
            summary.unwrap_or_else(|| type_name.unwrap_or_else(|| "Activity".to_string())),
            due_date.format("%Y-%m-%d"),
            assigned_to.unwrap_or_else(|| "Unassigned".to_string()),
            action_btn,
            state_badge
        ));
    }

    if activities_html.is_empty() {
        activities_html = r#"<div class="text-center text-base-content/50 py-4">No activities scheduled</div>"#.to_string();
    }

    // Build attachments HTML
    let mut attachments_html = String::new();
    let is_admin = user.roles.iter().any(|r| r == "admin" || r == "Admin");

    for att in &attachments {
        let att_id: uuid::Uuid = att.get("id");
        let name: String = att.get("name");
        let file_size: i64 = att.get("file_size");
        let mime_type: Option<String> = att.get("mime_type");
        let created_at: chrono::DateTime<chrono::Utc> = att.get("created_at");
        let uploaded_by: Option<String> = att.get("uploaded_by");
        let is_secure: bool = att.try_get("is_secure").unwrap_or(false);
        let created_by_id: Option<uuid::Uuid> = att.try_get("created_by").ok();

        // Check if user can delete (owner or admin)
        let can_delete = is_admin || created_by_id == Some(user.id);

        // Format file size
        let size_str = if file_size < 1024 {
            format!("{} B", file_size)
        } else if file_size < 1024 * 1024 {
            format!("{:.1} KB", file_size as f64 / 1024.0)
        } else {
            format!("{:.1} MB", file_size as f64 / (1024.0 * 1024.0))
        };

        // Icon based on mime type and security
        let icon = if is_secure {
            r#"<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-warning" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>"#
        } else {
            match mime_type.as_deref() {
                Some(m) if m.starts_with("image/") => r#"<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>"#,
                Some(m) if m.contains("pdf") => r#"<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>"#,
                _ => r#"<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"/></svg>"#,
            }
        };

        // Check if previewable (PDF or image)
        let is_pdf = mime_type.as_deref().map(|m| m.contains("pdf")).unwrap_or(false);
        let is_image = mime_type.as_deref().map(|m| m.starts_with("image/")).unwrap_or(false);

        // Preview button - inline onclick using data attributes
        let eye_icon = r#"<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>"#;

        // Preview button. All rendering lives in vortex.js
        // (vortexOpenPreview) — PDFs render via pdf.js to <canvas> so they
        // display on iOS Safari (which won't show a PDF in an <iframe>) and so
        // secure docs keep a per-page watermark with no savable file. Here we
        // just emit the button carrying the data the JS needs.
        let preview_btn = if is_pdf || is_image {
            let kind = if is_pdf { "pdf" } else { "image" };
            let wm = html_escape(&format!("{} - CONFIDENTIAL", user.username));
            format!(
                r#"<button type="button" class="btn btn-ghost btn-xs opacity-0 group-hover:opacity-100" onclick="vortexOpenPreview(this)" data-kind="{kind}" data-secure="{secure}" data-t="{name}" data-u="/api/chatter/attachments/{id}/download" data-wm="{wm}" title="Preview">{icon}</button>"#,
                kind = kind,
                secure = if is_secure { "1" } else { "0" },
                name = html_escape(&name),
                id = att_id,
                wm = wm,
                icon = eye_icon,
            )
        } else {
            String::new()
        };

        // Download link - only for non-secure documents
        let name_display = if is_secure {
            format!(r#"<span class="font-medium truncate block">{}</span>"#, name)
        } else {
            format!(r#"<a href="/api/chatter/attachments/{}/download" class="font-medium hover:underline truncate block">{}</a>"#, att_id, name)
        };

        // Delete button - only if user has permission
        let delete_btn = if can_delete {
            format!(
                r##"<button class="btn btn-ghost btn-xs opacity-0 group-hover:opacity-100"
                        hx-delete="/api/chatter/attachments/{}"
                        hx-target="#activity-stream"
                        hx-swap="innerHTML"
                        hx-confirm="Delete this attachment?">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                </button>"##,
                att_id
            )
        } else {
            String::new()
        };

        // Security badge
        let secure_badge = if is_secure {
            r##"<span class="badge badge-warning badge-xs">Secure</span>"##
        } else {
            ""
        };

        attachments_html.push_str(&format!(
            r##"<div class="flex items-center gap-3 p-2 rounded hover:bg-base-200 group">
                <div class="text-base-content/70">{}</div>
                <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2">{} {}</div>
                    <div class="text-xs text-base-content/60">{} - {} - {}</div>
                </div>
                <div class="flex gap-1">
                    {}
                    {}
                </div>
            </div>"##,
            icon, name_display, secure_badge, size_str, uploaded_by.unwrap_or_else(|| "Unknown".to_string()), created_at.format("%Y-%m-%d"), preview_btn, delete_btn
        ));
    }

    if attachments_html.is_empty() {
        attachments_html = r#"<div class="text-center text-base-content/50 py-4">No attachments</div>"#.to_string();
    }

    let attachment_count = attachments.len();

    // Build activity type options
    let mut type_options = String::new();
    for at in &activity_types {
        let id: uuid::Uuid = at.get("id");
        let name: String = at.get("name");
        type_options.push_str(&format!(r#"<option value="{}">{}</option>"#, id, name));
    }

    // Build user options
    let mut user_options = String::new();
    for u in &assignable_users {
        let id: uuid::Uuid = u.get("id");
        let username: String = u.get("username");
        let selected = if id == user.id { " selected" } else { "" };
        user_options.push_str(&format!(r#"<option value="{}"{}>@{}</option>"#, id, selected, username));
    }

    // Default due date to tomorrow
    let tomorrow = (chrono::Utc::now() + chrono::Duration::days(1)).format("%Y-%m-%d");

    // Plain inline count — a daisyUI badge box overflows the fixed-height
    // boxed tab on mobile (clips below the tab). "(N)" never overflows.
    let attachment_badge = if attachment_count > 0 {
        format!(r#"<span class="ml-1 opacity-60">({})</span>"#, attachment_count)
    } else {
        String::new()
    };

    // Inline tab switch logic - no external function needed
    let switch_to_messages = "document.querySelectorAll('.stream-tab').forEach(t=>t.classList.add('hidden'));document.querySelectorAll('.stream-tab-btn').forEach(b=>b.classList.remove('tab-active'));document.getElementById('messages-tab').classList.remove('hidden');this.classList.add('tab-active');";
    let switch_to_activities = "document.querySelectorAll('.stream-tab').forEach(t=>t.classList.add('hidden'));document.querySelectorAll('.stream-tab-btn').forEach(b=>b.classList.remove('tab-active'));document.getElementById('activities-tab').classList.remove('hidden');this.classList.add('tab-active');";
    let switch_to_attachments = "document.querySelectorAll('.stream-tab').forEach(t=>t.classList.add('hidden'));document.querySelectorAll('.stream-tab-btn').forEach(b=>b.classList.remove('tab-active'));document.getElementById('attachments-tab').classList.remove('hidden');this.classList.add('tab-active');";

    let html = format!(
        "<div class=\"card bg-base-100 shadow\">\
            <div class=\"card-body p-4\">\
                <h3 class=\"text-sm font-semibold text-base-content/70 mb-3\">Activity Stream</h3>\
                <div class=\"tabs tabs-boxed mb-4\">\
                    <a class=\"tab tab-active stream-tab-btn\" id=\"messages-btn\" onclick=\"{}\">Messages</a>\
                    <a class=\"tab stream-tab-btn\" id=\"activities-btn\" onclick=\"{}\">Activities</a>\
                    <a class=\"tab stream-tab-btn\" id=\"attachments-btn\" onclick=\"{}\">Attachments {}</a>\
                </div>\
                <div id=\"messages-tab\" class=\"stream-tab\">\
                    <form hx-post=\"/api/chatter/{}/{}/messages\" hx-target=\"#activity-stream\" hx-swap=\"innerHTML\" class=\"mb-4\">\
                        <textarea name=\"body\" class=\"textarea textarea-bordered w-full\" rows=\"2\" placeholder=\"Write a message...\"></textarea>\
                        <div class=\"flex justify-end gap-2 mt-2\">\
                            <label class=\"label cursor-pointer gap-2\">\
                                <input type=\"checkbox\" name=\"is_internal\" class=\"checkbox checkbox-sm\"/>\
                                <span class=\"label-text text-xs\">Internal note</span>\
                            </label>\
                            <button type=\"submit\" class=\"btn btn-primary btn-sm\">Post</button>\
                        </div>\
                    </form>\
                    <div class=\"max-h-96 overflow-y-auto\">{}</div>\
                </div>\
                <div id=\"activities-tab\" class=\"stream-tab hidden\">\
                    <button class=\"btn btn-primary btn-sm mb-4\" onclick=\"document.getElementById('activity-modal').showModal();\">+ Schedule Activity</button>\
                    <div class=\"max-h-96 overflow-y-auto\">{}</div>\
                </div>\
                <div id=\"attachments-tab\" class=\"stream-tab hidden\">\
                    <form hx-post=\"/api/chatter/{}/{}/attachments\" hx-target=\"#activity-stream\" hx-swap=\"innerHTML\" hx-encoding=\"multipart/form-data\" class=\"mb-4\">\
                        <div class=\"flex gap-2 items-center flex-wrap\">\
                            <input type=\"file\" name=\"file\" class=\"file-input file-input-bordered file-input-sm flex-1\" required/>\
                            <label class=\"label cursor-pointer gap-2\">\
                                <input type=\"checkbox\" name=\"is_secure\" class=\"checkbox checkbox-sm checkbox-warning\"/>\
                                <span class=\"label-text text-xs flex items-center gap-1\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"w-3 h-3\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z\"/></svg>Secure</span>\
                            </label>\
                            <button type=\"submit\" class=\"btn btn-primary btn-sm\">Upload</button>\
                        </div>\
                    </form>\
                    <div class=\"max-h-96 overflow-y-auto\">{}</div>\
                </div>\
            </div>\
        </div>\
        <dialog id=\"activity-modal\" class=\"modal\">\
            <div class=\"modal-box\">\
                <h3 class=\"font-bold text-lg mb-4\">Schedule Activity</h3>\
                <form hx-post=\"/api/chatter/{}/{}/activities\" hx-target=\"#activity-stream\" hx-swap=\"innerHTML\" hx-on::after-request=\"document.getElementById('activity-modal').close();\">\
                    <div class=\"form-control mb-3\">\
                        <label class=\"label\"><span class=\"label-text\">Activity Type</span></label>\
                        <select name=\"activity_type_id\" class=\"select select-bordered w-full\" required>{}</select>\
                    </div>\
                    <div class=\"form-control mb-3\">\
                        <label class=\"label\"><span class=\"label-text\">Summary</span></label>\
                        <input type=\"text\" name=\"summary\" class=\"input input-bordered w-full\" placeholder=\"What needs to be done?\" required/>\
                    </div>\
                    <div class=\"form-control mb-3\">\
                        <label class=\"label\"><span class=\"label-text\">Due Date</span></label>\
                        <input type=\"date\" name=\"due_date\" class=\"input input-bordered w-full\" value=\"{}\" required/>\
                    </div>\
                    <div class=\"form-control mb-3\">\
                        <label class=\"label\"><span class=\"label-text\">Assigned To</span></label>\
                        <select name=\"assigned_to_id\" class=\"select select-bordered w-full\">{}</select>\
                    </div>\
                    <div class=\"form-control mb-4\">\
                        <label class=\"label\"><span class=\"label-text\">Note (optional)</span></label>\
                        <textarea name=\"note\" class=\"textarea textarea-bordered w-full\" rows=\"2\" placeholder=\"Additional details...\"></textarea>\
                    </div>\
                    <div class=\"modal-action\">\
                        <button type=\"button\" class=\"btn\" onclick=\"document.getElementById('activity-modal').close();\">Cancel</button>\
                        <button type=\"submit\" class=\"btn btn-primary\">Schedule</button>\
                    </div>\
                </form>\
            </div>\
            <form method=\"dialog\" class=\"modal-backdrop\"><button>close</button></form>\
        </dialog>\
        <dialog id=\"preview-modal\" class=\"modal\">\
            <div class=\"modal-box w-11/12 max-w-5xl h-[85vh] flex flex-col\">\
                <div class=\"flex justify-between items-center mb-4\">\
                    <h3 class=\"font-bold text-lg\" id=\"preview-title\">Preview</h3>\
                    <div class=\"flex gap-2\">\
                        <a id=\"preview-download\" href=\"#\" class=\"btn btn-sm btn-ghost\" download>Download</a>\
                        <button class=\"btn btn-sm btn-circle btn-ghost\" onclick=\"document.getElementById('preview-modal').close();\">✕</button>\
                    </div>\
                </div>\
                <div id=\"preview-content\" class=\"flex-1 overflow-hidden bg-base-200 rounded-lg\"></div>\
            </div>\
            <form method=\"dialog\" class=\"modal-backdrop\"><button>close</button></form>\
        </dialog>",
        switch_to_messages, switch_to_activities, switch_to_attachments, attachment_badge, model, record_id, messages_html, activities_html, model, record_id, attachments_html, model, record_id, type_options, tomorrow, user_options
    );
    Html(html).into_response()
}

/// Form data for posting a chatter message
#[derive(Debug, serde::Deserialize)]
struct ChatterMessageForm {
    body: String,
    is_internal: Option<String>,
}

/// Post a message to chatter
async fn chatter_post_message(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
    Form(form): Form<ChatterMessageForm>,
) -> Response {
    if form.body.trim().is_empty() {
        return chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await;
    }

    // Get user's company_id
    let company_id: uuid::Uuid = match sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&db)
        .await
    {
        Ok(cid) => cid,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Html("Error")).into_response(),
    };

    let msg_id = uuid::Uuid::now_v7();
    let is_internal = form.is_internal.is_some();
    let msg_type = if is_internal { "note" } else { "comment" };

    if let Err(e) = sqlx::query(
        "INSERT INTO chatter_messages (id, res_model, res_id, message_type, body, author_id, is_internal, company_id, created_at, active, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), true, $9)"
    )
    .bind(msg_id)
    .bind(&model)
    .bind(record_id)
    .bind(msg_type)
    .bind(form.body.trim())
    .bind(user.id)
    .bind(is_internal)
    .bind(company_id)
    .bind(user.id)
    .execute(&db)
    .await {
        error!("Failed to post message: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    // Return updated chatter panel
    chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await
}

/// Form data for scheduling an activity
#[derive(Debug, serde::Deserialize)]
struct ChatterActivityForm {
    activity_type_id: uuid::Uuid,
    summary: String,
    due_date: String,
    assigned_to_id: Option<uuid::Uuid>,
    note: Option<String>,
}

/// Schedule an activity
async fn chatter_post_activity(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
    Form(form): Form<ChatterActivityForm>,
) -> Response {
    if form.summary.trim().is_empty() {
        return chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await;
    }

    // Get user's company_id
    let company_id: uuid::Uuid = match sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&db)
        .await
    {
        Ok(cid) => cid,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Html("Error")).into_response(),
    };

    // Parse due date
    let due_date = match chrono::NaiveDate::parse_from_str(&form.due_date, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => return (StatusCode::BAD_REQUEST, Html("Invalid date format")).into_response(),
    };

    let activity_id = uuid::Uuid::now_v7();
    let assigned_to = form.assigned_to_id.unwrap_or(user.id);

    if let Err(e) = sqlx::query(
        "INSERT INTO chatter_activities (id, res_model, res_id, activity_type_id, summary, note, due_date, assigned_to_id, assigned_by_id, state, company_id, created_at, created_by, active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, NOW(), $9, true)"
    )
    .bind(activity_id)
    .bind(&model)
    .bind(record_id)
    .bind(form.activity_type_id)
    .bind(form.summary.trim())
    .bind(form.note.as_deref().unwrap_or(""))
    .bind(due_date)
    .bind(assigned_to)
    .bind(user.id)
    .bind(company_id)
    .execute(&db)
    .await {
        error!("Failed to schedule activity: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    // Return updated chatter panel
    chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await
}

/// Mark an activity as completed
async fn chatter_complete_activity(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id, activity_id)): Path<(String, uuid::Uuid, uuid::Uuid)>,
) -> Response {
    if let Err(e) = sqlx::query(
        "UPDATE chatter_activities SET state = 'completed', completed_at = NOW(), completed_by = $1 WHERE id = $2"
    )
    .bind(user.id)
    .bind(activity_id)
    .execute(&db)
    .await {
        error!("Failed to complete activity: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    // Return updated chatter panel
    chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await
}

/// Mark an activity as completed and open schedule modal for next activity
async fn chatter_complete_and_schedule(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id, activity_id)): Path<(String, uuid::Uuid, uuid::Uuid)>,
) -> Response {
    // Get the activity type info before completing
    let activity_info: Option<(uuid::Uuid, i32)> = sqlx::query_as(
        "SELECT t.id, COALESCE(t.default_days, 1) FROM chatter_activities a
         JOIN chatter_activity_types t ON a.activity_type_id = t.id
         WHERE a.id = $1"
    )
    .bind(activity_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    if let Err(e) = sqlx::query(
        "UPDATE chatter_activities SET state = 'completed', completed_at = NOW(), completed_by = $1 WHERE id = $2"
    )
    .bind(user.id)
    .bind(activity_id)
    .execute(&db)
    .await {
        error!("Failed to complete activity: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    // Return updated chatter panel with script to open modal and pre-fill
    let panel = chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await;
    let panel_html = match axum::body::to_bytes(panel.into_body(), usize::MAX).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Html("Error")).into_response(),
    };

    // Calculate next due date based on activity type's default_days
    let (type_id, default_days) = activity_info.unwrap_or((uuid::Uuid::nil(), 1));
    let next_due = (chrono::Utc::now() + chrono::Duration::days(default_days as i64)).format("%Y-%m-%d");

    // Add script to auto-open the modal and pre-fill values
    let html = format!(
        "{}<script>setTimeout(function(){{\
            document.getElementById('activity-modal').showModal();\
            var typeSelect = document.querySelector('select[name=\"activity_type_id\"]');\
            if(typeSelect) typeSelect.value = '{}';\
            var dueDateInput = document.querySelector('input[name=\"due_date\"]');\
            if(dueDateInput) dueDateInput.value = '{}';\
        }}, 100);</script>",
        panel_html, type_id, next_due
    );
    Html(html).into_response()
}

// ============================================================================
// Chatter Attachments
// ============================================================================


async fn chatter_upload_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
    mut multipart: Multipart,
) -> Response {
    // Get user's company_id
    let company_id: uuid::Uuid = match sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&db)
        .await
    {
        Ok(cid) => cid,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Html("Error getting company")).into_response(),
    };

    // Collect form fields - file and is_secure checkbox
    let mut file_data: Option<(String, Option<String>, Vec<u8>)> = None;
    let mut is_secure = false;

    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();

        if field_name == "is_secure" {
            // Checkbox is present = checked
            is_secure = true;
        } else if field_name == "file" {
            let file_name = field.file_name().unwrap_or("unknown").to_string();
            let content_type = field.content_type().map(|s| s.to_string());
            match field.bytes().await {
                Ok(d) => file_data = Some((file_name, content_type, d.to_vec())),
                Err(e) => return (StatusCode::BAD_REQUEST, Html(format!("Failed to read file: {}", e))).into_response(),
            }
        }
    }

    let Some((file_name, content_type, data)) = file_data else {
        return (StatusCode::BAD_REQUEST, Html("No file provided")).into_response();
    };

    let file_size: i64 = data.len() as i64;

    // Storage key doubles as the chatter "file path" column value —
    // it's a FileStore key now, not a filesystem path.
    let store_key = new_store_key("chatter/", &file_name);
    let store_fname = store_key.rsplit('/').next().unwrap_or(&store_key).to_string();

    // Compute checksum
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let checksum = hex::encode(hasher.finalize());

    // Persist the blob under the tenant's namespace
    if let Err(e) = state
        .files
        .put(&db_ctx.db_name, &store_key, &data, content_type.as_deref())
        .await
    {
        error!("chatter attachment store failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, Html("Failed to store file".to_string())).into_response();
    }

    // Insert record with is_secure flag
    let result = sqlx::query(
        "INSERT INTO chatter_attachments (name, file_name, file_path, file_size, mime_type, checksum, res_model, res_id, company_id, created_by, is_secure)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id"
    )
    .bind(&file_name)
    .bind(&store_fname)
    .bind(&store_key)
    .bind(file_size)
    .bind(&content_type)
    .bind(&checksum)
    .bind(&model)
    .bind(record_id)
    .bind(company_id)
    .bind(user.id)
    .bind(is_secure)
    .fetch_one(&db)
    .await;

    if let Err(e) = result {
        // Clean up blob on error so no orphan survives
        let _ = state.files.delete(&db_ctx.db_name, &store_key).await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Database error: {}", e))).into_response();
    }

    // Return updated activity stream
    chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await
}

async fn chatter_download_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let attachment = sqlx::query(
        "SELECT name, file_path, mime_type, is_secure FROM chatter_attachments WHERE id = $1 AND active = true"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(att) = attachment else {
        return (StatusCode::NOT_FOUND, "Attachment not found").into_response();
    };

    let name: String = att.get("name");
    let file_path: String = att.get("file_path");
    let mimetype: Option<String> = att.get("mime_type");
    let is_secure: bool = att.try_get("is_secure").unwrap_or(false);

    // For secure documents, only allow inline viewing (no direct download)
    // Check if this is a download request vs preview request
    let is_download_request = params.get("download").is_some();
    if is_secure && is_download_request {
        return (StatusCode::FORBIDDEN, "Secure documents cannot be downloaded").into_response();
    }

    let data = match state.files.get(&db_ctx.db_name, &file_path).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "File not found in storage").into_response(),
        Err(e) => {
            error!("chatter attachment fetch failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Storage error").into_response();
        }
    };

    let content_type = mimetype.unwrap_or_else(|| "application/octet-stream".to_string());

    // For secure documents, always inline (no download prompt)
    // For others, use inline for previewable types, attachment for others
    let disposition = if is_secure {
        // Force inline, no filename to discourage save-as
        "inline".to_string()
    } else if content_type.contains("pdf") || content_type.starts_with("image/") {
        format!("inline; filename=\"{}\"", name)
    } else {
        format!("attachment; filename=\"{}\"", name)
    };

    // For secure documents, add headers to prevent caching
    if is_secure {
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CONTENT_DISPOSITION, disposition),
                (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate, private".to_string()),
                (header::PRAGMA, "no-cache".to_string()),
                (header::EXPIRES, "0".to_string()),
            ],
            data,
        ).into_response()
    } else {
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CONTENT_DISPOSITION, disposition),
            ],
            data,
        ).into_response()
    }
}

async fn chatter_delete_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Get the attachment info first
    let attachment = sqlx::query(
        "SELECT file_path, res_model, res_id, created_by FROM chatter_attachments WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(att) = attachment else {
        return (StatusCode::NOT_FOUND, "Attachment not found").into_response();
    };

    let file_path: String = att.get("file_path");
    let model: String = att.get("res_model");
    let record_id: uuid::Uuid = att.get("res_id");
    let created_by: Option<uuid::Uuid> = att.try_get("created_by").ok();

    // Check permission - only owner or admin can delete
    let is_admin = user.roles.iter().any(|r| r == "admin" || r == "Admin");
    let is_owner = created_by == Some(user.id);
    if !is_admin && !is_owner {
        return (StatusCode::FORBIDDEN, "You don't have permission to delete this attachment").into_response();
    }

    // Soft delete (set active = false)
    if let Err(e) = sqlx::query("UPDATE chatter_attachments SET active = false WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {}", e)).into_response();
    }

    // Remove the blob from storage (row is only soft-deleted above,
    // but the file itself is gone — matches previous behavior)
    let _ = state.files.delete(&db_ctx.db_name, &file_path).await;

    // Return updated chatter panel
    chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await
}

// ============================================================================
// Notifications Page
// ============================================================================

async fn notifications_page(
    Extension(user): Extension<AuthUser>,
) -> Response {
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notifications - Remicle</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
    <script src="/static/vendor/tailwind.js"></script>
    <style>
        body {{ background: oklch(var(--b2)); color: oklch(var(--bc)); }}
        .navbar {{ background: oklch(var(--b1)); border-bottom: 1px solid oklch(var(--b3)); }}
        .card {{ background: oklch(var(--b1)); border: 1px solid oklch(var(--b3)); }}
        .card:hover {{ background: oklch(var(--b3)); }}
        .text-muted {{ color: oklch(var(--bc)/0.6); }}
        .user-badge {{ background: #8BC53F; color: #000; font-weight: 600; }}
        .notif-unread {{ border-left: 3px solid #8BC53F; }}
    </style>
</head>
<body class="min-h-screen">
    <div class="navbar px-4 sticky top-0 z-50">
        <div class="flex-1">
            <a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a>
        </div>
        <div class="flex items-center gap-2 md:gap-3">
            <a href="/home" class="text-base-content text-sm hover:underline hidden md:inline">Home</a>
            <a href="/settings" class="text-base-content text-sm hover:underline hidden md:inline">Settings</a>
            <a href="/notifications" class="btn btn-ghost btn-circle btn-sm relative" title="Notifications">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
                <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
            </a>
            <button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-circle btn-sm" title="Toggle theme"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button>
        <div class="user-badge px-3 py-1 rounded-full text-sm">@{}</div>
        </div>
    </div>

    <div class="container mx-auto px-4 py-6 max-w-3xl">
        <div class="mb-6">
            <h1 class="text-2xl md:text-3xl font-bold">Notifications</h1>
            <p class="text-muted mt-1">Stay updated on activities and alerts</p>
        </div>

        <div class="space-y-3">
            <div class="card notif-unread p-4 cursor-pointer">
                <div class="flex items-start gap-3">
                    <div class="w-10 h-10 rounded-full flex items-center justify-center" style="background:rgba(139,197,63,0.2)">
                        <svg class="w-5 h-5" style="color:#8BC53F" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    </div>
                    <div class="flex-1">
                        <p class="font-medium">Change Request CR-2024-001 Approved</p>
                        <p class="text-muted text-sm mt-1">Your change request has been approved by the supervisor.</p>
                        <p class="text-muted text-xs mt-2">2 hours ago</p>
                    </div>
                </div>
            </div>

            <div class="card notif-unread p-4 cursor-pointer">
                <div class="flex items-start gap-3">
                    <div class="w-10 h-10 rounded-full flex items-center justify-center" style="background:rgba(59,130,246,0.2)">
                        <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/></svg>
                    </div>
                    <div class="flex-1">
                        <p class="font-medium">New comment on Contact C-1001</p>
                        <p class="text-muted text-sm mt-1">John mentioned you in a comment.</p>
                        <p class="text-muted text-xs mt-2">5 hours ago</p>
                    </div>
                </div>
            </div>

            <div class="card p-4 cursor-pointer opacity-70">
                <div class="flex items-start gap-3">
                    <div class="w-10 h-10 rounded-full flex items-center justify-center" style="background:rgba(245,158,11,0.2)">
                        <svg class="w-5 h-5 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    </div>
                    <div class="flex-1">
                        <p class="font-medium">Scheduled task reminder</p>
                        <p class="text-muted text-sm mt-1">Record R-1005 is due for review tomorrow.</p>
                        <p class="text-muted text-xs mt-2">1 day ago</p>
                    </div>
                </div>
            </div>

            <div class="card p-4 cursor-pointer opacity-70">
                <div class="flex items-start gap-3">
                    <div class="w-10 h-10 rounded-full flex items-center justify-center" style="background:rgba(139,197,63,0.2)">
                        <svg class="w-5 h-5" style="color:#8BC53F" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                    </div>
                    <div class="flex-1">
                        <p class="font-medium">Task completed</p>
                        <p class="text-muted text-sm mt-1">Review task for record R-101 has been completed.</p>
                        <p class="text-muted text-xs mt-2">2 days ago</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="mt-8 text-center">
            <p class="text-muted text-sm">End of notifications</p>
        </div>
    </div>
</body>
</html>"##,
        user.username
    );

    Html(html).into_response()
}

// ============================================================================
// Settings Index
// ============================================================================

async fn settings_index(
    Extension(user): Extension<AuthUser>,
) -> Response {
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - Remicle</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
    <script src="/static/vendor/tailwind.js"></script>
    <style>
        body {{ background: oklch(var(--b2)); color: oklch(var(--bc)); }}
        .card {{ background: oklch(var(--b1)); border: 1px solid oklch(var(--b3)); }}
        .card:hover {{ background: oklch(var(--b3)); border-color: oklch(var(--b3)); }}
        .card-title {{ color: oklch(var(--bc)); font-weight: 600; }}
        .text-muted {{ color: oklch(var(--bc)/0.6); }}
        .section-title {{ color: #8BC53F; }}
        .navbar {{ background: oklch(var(--b1)); border-bottom: 1px solid oklch(var(--b3)); }}
        @media (max-width: 768px) {{
            .card-body {{ padding: 1rem; }}
            .card-title {{ font-size: 1.1rem; }}
            .text-muted {{ font-size: 0.9rem; }}
            h1 {{ font-size: 1.75rem; }}
            .section-title {{ font-size: 1.1rem; }}
        }}
    </style>
</head>
<body class="min-h-screen">
    <div class="navbar px-4 sticky top-0 z-50">
        <div class="flex-1">
            <a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a>
        </div>
        <div class="flex items-center gap-2 md:gap-3">
            <a href="/home" class="text-base-content text-sm hover:underline hidden md:inline">Home</a>
            <a href="/notifications" class="btn btn-ghost btn-circle btn-sm relative" title="Notifications">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
                <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
            </a>
            <button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-circle btn-sm" title="Toggle theme"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button>
            <div style="background:#8BC53F;color:#000;font-weight:600" class="px-3 py-1 rounded-full text-sm">@{}</div>
        </div>
    </div>

    <div class="container mx-auto px-4 py-6 max-w-5xl">
        <div class="mb-8">
            <h1 class="text-2xl md:text-3xl font-bold">Settings</h1>
            <p class="text-muted mt-1">System configuration and administration</p>
        </div>

        <!-- Appearance Section -->
        <div class="mb-8">
            <h2 class="section-title text-lg font-semibold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
                Appearance
            </h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 md:gap-4">
                <div onclick="document.documentElement.setAttribute('data-theme','dark');localStorage.setItem('theme','dark');document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}});document.querySelectorAll('.theme-card').forEach(function(c){{c.classList.remove('ring-2','ring-primary')}});this.classList.add('ring-2','ring-primary')" class="card transition-all cursor-pointer theme-card" id="theme-dark">
                    <div class="card-body p-4 flex flex-row items-center gap-4">
                        <div class="w-12 h-12 rounded-lg flex items-center justify-center shrink-0" style="background:#1a1a2e;border:1px solid #2a2a4a">
                            <svg class="w-6 h-6" style="color:#e8e8e8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>
                        </div>
                        <div>
                            <h3 class="card-title text-base md:text-lg">Dark</h3>
                            <p class="text-muted text-sm">Dark background, light text</p>
                        </div>
                    </div>
                </div>
                <div onclick="document.documentElement.setAttribute('data-theme','corporate');localStorage.setItem('theme','corporate');document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}});document.querySelectorAll('.theme-card').forEach(function(c){{c.classList.remove('ring-2','ring-primary')}});this.classList.add('ring-2','ring-primary')" class="card transition-all cursor-pointer theme-card" id="theme-light">
                    <div class="card-body p-4 flex flex-row items-center gap-4">
                        <div class="w-12 h-12 rounded-lg flex items-center justify-center shrink-0" style="background:#f5f5f5;border:1px solid #e0e0e0">
                            <svg class="w-6 h-6" style="color:#333" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
                        </div>
                        <div>
                            <h3 class="card-title text-base md:text-lg">Light</h3>
                            <p class="text-muted text-sm">Light background, dark text</p>
                        </div>
                    </div>
                </div>
            </div>
            <script>(function(){{var t=localStorage.getItem('theme')||'dark';var el=document.getElementById(t==='corporate'?'theme-light':'theme-dark');if(el)el.classList.add('ring-2','ring-primary')}})();</script>
        </div>

        <!-- Users & Access Section -->
        <div class="mb-8">
            <h2 class="section-title text-lg font-semibold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m9 5.197v-1"/></svg>
                Users & Access
            </h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 md:gap-4">
                <a href="/users" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Users</h3>
                        <p class="text-muted text-sm">Manage user accounts</p>
                    </div>
                </a>
                <a href="/list/roles" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Roles</h3>
                        <p class="text-muted text-sm">User roles & permissions</p>
                    </div>
                </a>
                <a href="/admin/access" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Access Control</h3>
                        <p class="text-muted text-sm">Model & record rules</p>
                    </div>
                </a>
            </div>
        </div>

        <!-- Organization Section -->
        <div class="mb-8">
            <h2 class="section-title text-lg font-semibold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>
                Organization
            </h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 md:gap-4">
                <a href="/list/companies" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Companies</h3>
                        <p class="text-muted text-sm">Multi-company setup</p>
                    </div>
                </a>
                <a href="/modules" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Apps & Modules</h3>
                        <p class="text-muted text-sm">Installed applications</p>
                    </div>
                </a>
            </div>
        </div>

        <!-- Localization Section -->
        <div class="mb-8">
            <h2 class="section-title text-lg font-semibold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                Localization
            </h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 md:gap-4">
                <a href="/settings/countries" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Countries</h3>
                        <p class="text-muted text-sm">Maintain the country master list</p>
                    </div>
                </a>
                <a href="/settings/states" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">States / Provinces</h3>
                        <p class="text-muted text-sm">Maintain states per country</p>
                    </div>
                </a>
                <a href="/settings/stages" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Stages</h3>
                        <p class="text-muted text-sm">Status-bar stages per model</p>
                    </div>
                </a>
                <a href="/settings/stage-buttons" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Stage Buttons</h3>
                        <p class="text-muted text-sm">Role-gated status transition buttons</p>
                    </div>
                </a>
                <a href="/settings/approval-rules" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Approval Rules</h3>
                        <p class="text-muted text-sm">Multi-step sign-off for stage buttons</p>
                    </div>
                </a>
                <a href="/settings/email" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Email / SMTP</h3>
                        <p class="text-muted text-sm">Outbound mail servers (Gmail, Office 365, …)</p>
                    </div>
                </a>
                <a href="/settings/jobs" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Background Jobs</h3>
                        <p class="text-muted text-sm">Durable queue: retries, dead-letter, status</p>
                    </div>
                </a>
                <a href="/settings/api-tokens" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">API Tokens</h3>
                        <p class="text-muted text-sm">Bearer credentials for the public REST API</p>
                    </div>
                </a>
                <a href="/settings/webhooks" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Webhooks</h3>
                        <p class="text-muted text-sm">Outbound event subscriptions (signed, retried)</p>
                    </div>
                </a>
                <a href="/settings/portal-users" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Portal Users</h3>
                        <p class="text-muted text-sm">Invite customers to the self-service portal</p>
                    </div>
                </a>
            </div>
        </div>

        <!-- Technical Section -->
        <div class="mb-8">
            <h2 class="section-title text-lg font-semibold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                Technical
            </h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 md:gap-4">
                <a href="/settings/sequences" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Sequences</h3>
                        <p class="text-muted text-sm">Auto-numbering for documents</p>
                    </div>
                </a>
                <a href="/settings/cron" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Scheduled Jobs</h3>
                        <p class="text-muted text-sm">Background task scheduling</p>
                    </div>
                </a>
                <a href="/settings/reports" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Reports</h3>
                        <p class="text-muted text-sm">Print templates & documents</p>
                    </div>
                </a>
                <a href="/settings/activity-types" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Activity Types</h3>
                        <p class="text-muted text-sm">Activity types for Activity Stream</p>
                    </div>
                </a>
                <a href="/settings/custom-fields" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Custom Fields</h3>
                        <p class="text-muted text-sm">Add your own fields to any model — no code</p>
                    </div>
                </a>
                <a href="/settings/automation-rules" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Automation Rules</h3>
                        <p class="text-muted text-sm">React to record changes automatically — no code</p>
                    </div>
                </a>
                <a href="/settings/computed-fields" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Computed Fields</h3>
                        <p class="text-muted text-sm">Derived fields: formulas &amp; related values — no code</p>
                    </div>
                </a>
                <a href="/dashboards" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Dashboards</h3>
                        <p class="text-muted text-sm">Build KPI &amp; breakdown boards from any model</p>
                    </div>
                </a>
            </div>
        </div>

        <!-- Documents Section -->
        <div class="mb-8">
            <h2 class="section-title text-lg font-semibold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                Documents
            </h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 md:gap-4">
                <a href="/settings/document-layout" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Document Layout</h3>
                        <p class="text-muted text-sm">Logo, brand colour &amp; footer on printed documents</p>
                    </div>
                </a>
                <a href="/settings/print-templates" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Print Templates</h3>
                        <p class="text-muted text-sm">Customise the layout of quotations &amp; other documents</p>
                    </div>
                </a>
            </div>
        </div>
    </div>
</body>
</html>"##,
        user.username
    );

    Html(html).into_response()
}

// ============================================================================
// Audit Log viewer — read-only window over the WORM ledger
//
// The audit *engine* (append-only, hash-chained, optionally signed) lives in
// vortex-security. This page is the operator-facing view: filter by user /
// action / resource / date, page through entries, run an on-demand chain
// integrity check, and export the filtered set as CSV. Admin-only.
// ============================================================================

/// CSV-escape a single field (RFC 4180): wrap in quotes, double inner quotes.
fn csv_field(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

async fn audit_log_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Audit Log"))).into_response();
    }

    // ── Read filters from the query string ──────────────────────────────
    let f_user = query.get("user").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let f_action = query.get("action").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let f_resource = query.get("resource").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let f_from = query.get("from").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let f_to = query.get("to").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let want_csv = query.get("format").map(|s| s.as_str()) == Some("csv");
    let do_verify = query.get("verify").map(|s| s.as_str()) == Some("1");
    let page: i64 = query.get("page").and_then(|s| s.parse().ok()).unwrap_or(0).max(0);
    const PAGE_SIZE: i64 = 50;

    // ── Build a parameterized WHERE from whichever filters are set ───────
    // All binds are strings; SQL casts the date filters. Order of `binds`
    // matches the $1,$2,… placeholders exactly.
    let mut conds: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if let Some(u) = &f_user {
        conds.push(format!("username ILIKE ${}", binds.len() + 1));
        binds.push(format!("%{}%", u));
    }
    if let Some(a) = &f_action {
        conds.push(format!("action = ${}", binds.len() + 1));
        binds.push(a.clone());
    }
    if let Some(r) = &f_resource {
        conds.push(format!("resource_type = ${}", binds.len() + 1));
        binds.push(r.clone());
    }
    if let Some(fr) = &f_from {
        conds.push(format!("timestamp >= ${}::date", binds.len() + 1));
        binds.push(fr.clone());
    }
    if let Some(t) = &f_to {
        conds.push(format!("timestamp < (${}::date + INTERVAL '1 day')", binds.len() + 1));
        binds.push(t.clone());
    }
    let where_clause = if conds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conds.join(" AND "))
    };

    // ── CSV export short-circuit (filtered set, capped) ─────────────────
    if want_csv {
        let sql = format!(
            "SELECT timestamp, COALESCE(username,'System') AS username, action, \
             COALESCE(resource_type,'') AS resource_type, COALESCE(resource_name,'') AS resource_name, \
             success, COALESCE(host(ip_address),'') AS ip, chain_position \
             FROM audit_log {} ORDER BY timestamp DESC LIMIT 10000",
            where_clause
        );
        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b);
        }
        let rows = q.fetch_all(&db).await.unwrap_or_default();
        let mut csv = String::from("timestamp,username,action,resource_type,resource_name,success,ip,chain_position\n");
        for r in &rows {
            let ts: chrono::DateTime<chrono::Utc> = r.get("timestamp");
            let username: String = r.get("username");
            let action: String = r.get("action");
            let rtype: String = r.get("resource_type");
            let rname: String = r.get("resource_name");
            let success: bool = r.get("success");
            let ip: String = r.get("ip");
            let pos: Option<i64> = r.get("chain_position");
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                csv_field(&ts.to_rfc3339()),
                csv_field(&username),
                csv_field(&action),
                csv_field(&rtype),
                csv_field(&rname),
                success,
                csv_field(&ip),
                pos.map(|p| p.to_string()).unwrap_or_default(),
            ));
        }
        return (
            [
                (axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"audit_log.csv\""),
            ],
            csv,
        )
            .into_response();
    }

    // ── Total count for pagination ──────────────────────────────────────
    let count_sql = format!("SELECT COUNT(*) FROM audit_log {}", where_clause);
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &binds {
        cq = cq.bind(b);
    }
    let total: i64 = cq.fetch_one(&db).await.unwrap_or(0);

    // ── Page of entries ─────────────────────────────────────────────────
    let data_sql = format!(
        "SELECT timestamp, COALESCE(username,'System') AS username, action, \
         COALESCE(resource_type,'') AS resource_type, COALESCE(resource_name,'') AS resource_name, \
         success, COALESCE(host(ip_address),'') AS ip, chain_position \
         FROM audit_log {} ORDER BY timestamp DESC LIMIT ${} OFFSET ${}",
        where_clause,
        binds.len() + 1,
        binds.len() + 2,
    );
    let mut dq = sqlx::query(&data_sql);
    for b in &binds {
        dq = dq.bind(b);
    }
    dq = dq.bind(PAGE_SIZE).bind(page * PAGE_SIZE);
    let rows = dq.fetch_all(&db).await.unwrap_or_default();

    // ── Distinct actions for the filter dropdown ────────────────────────
    let actions: Vec<String> = sqlx::query_scalar("SELECT DISTINCT action FROM audit_log ORDER BY action")
        .fetch_all(&db)
        .await
        .unwrap_or_default();

    // ── Optional on-demand chain integrity check ────────────────────────
    let verify_banner = if do_verify {
        match verify_chain(
            &db,
            &VerifyOptions {
                company: None,
                from: None,
                to: None,
                max_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
            },
        )
        .await
        {
            Ok(report) if report.companies_checked == 0 => {
                r#"<div class="alert alert-info mb-4"><span>No chained audit entries yet — nothing to verify.</span></div>"#.to_string()
            }
            Ok(report) if report.ok() => format!(
                r#"<div class="alert alert-success mb-4"><span>✓ Chain intact — verified {} entries across {} tenant(s) in {}ms.</span></div>"#,
                report.entries_verified, report.companies_checked, report.duration.as_millis()
            ),
            Ok(report) => {
                let mut detail = String::new();
                for f in report.failures.iter().take(10) {
                    detail.push_str(&format!(
                        "<li class=\"text-sm\">company {} · position {} · [{}] {}</li>",
                        f.company_id,
                        f.chain_position,
                        html_escape(f.kind.code()),
                        html_escape(&f.detail),
                    ));
                }
                format!(
                    r#"<div class="alert alert-error mb-4 flex-col items-start"><span>✗ Chain verification FAILED — {} failure(s) across {} entries.</span><ul class="list-disc ml-6 mt-2">{}</ul></div>"#,
                    report.failure_count(), report.entries_verified, detail
                )
            }
            Err(e) => format!(
                r#"<div class="alert alert-warning mb-4"><span>Could not run verification: {}</span></div>"#,
                html_escape(&e.to_string())
            ),
        }
    } else {
        String::new()
    };

    // ── Build table rows ────────────────────────────────────────────────
    let mut rows_html = String::new();
    for r in &rows {
        let ts: chrono::DateTime<chrono::Utc> = r.get("timestamp");
        let username: String = r.get("username");
        let action: String = r.get("action");
        let rtype: String = r.get("resource_type");
        let rname: String = r.get("resource_name");
        let success: bool = r.get("success");
        let ip: String = r.get("ip");
        let pos: Option<i64> = r.get("chain_position");

        let success_badge = if success {
            r#"<span class="badge badge-success badge-sm">OK</span>"#
        } else {
            r#"<span class="badge badge-error badge-sm">FAIL</span>"#
        };
        let resource_cell = if rname.is_empty() {
            html_escape(&rtype)
        } else {
            format!("{} <span class=\"text-base-content/50\">· {}</span>", html_escape(&rtype), html_escape(&rname))
        };
        rows_html.push_str(&format!(
            r##"<tr>
                <td class="whitespace-nowrap text-sm">{ts}</td>
                <td class="text-sm">{user}</td>
                <td><code class="text-xs">{action}</code></td>
                <td class="text-sm">{resource}</td>
                <td>{badge}</td>
                <td class="text-sm text-base-content/60">{ip}</td>
                <td class="text-xs text-base-content/50">{pos}</td>
            </tr>"##,
            ts = ts.format("%Y-%m-%d %H:%M:%S"),
            user = html_escape(&username),
            action = html_escape(&action),
            resource = resource_cell,
            badge = success_badge,
            ip = html_escape(&ip),
            pos = pos.map(|p| format!("#{p}")).unwrap_or_default(),
        ));
    }
    if rows.is_empty() {
        rows_html.push_str(r#"<tr><td colspan="7" class="text-center text-base-content/50 py-8">No audit entries match these filters.</td></tr>"#);
    }

    // ── Action filter dropdown options ──────────────────────────────────
    let mut action_options = String::from(r#"<option value="">All actions</option>"#);
    for a in &actions {
        let sel = if f_action.as_deref() == Some(a.as_str()) { " selected" } else { "" };
        action_options.push_str(&format!(r#"<option value="{a}"{sel}>{a}</option>"#, a = html_escape(a), sel = sel));
    }

    // ── Preserve filters across pagination / verify / export links ──────
    let enc = |s: &str| s.replace('%', "%25").replace(' ', "%20").replace('&', "%26").replace('#', "%23").replace('+', "%2B");
    let mut base_qs = String::new();
    if let Some(u) = &f_user { base_qs.push_str(&format!("&user={}", enc(u))); }
    if let Some(a) = &f_action { base_qs.push_str(&format!("&action={}", enc(a))); }
    if let Some(r) = &f_resource { base_qs.push_str(&format!("&resource={}", enc(r))); }
    if let Some(fr) = &f_from { base_qs.push_str(&format!("&from={}", enc(fr))); }
    if let Some(t) = &f_to { base_qs.push_str(&format!("&to={}", enc(t))); }

    let total_pages = if total == 0 { 1 } else { ((total - 1) / PAGE_SIZE) + 1 };
    let prev_link = if page > 0 {
        format!(r#"<a href="/audit?page={}{}" class="btn btn-sm btn-ghost">← Prev</a>"#, page - 1, base_qs)
    } else {
        r#"<button class="btn btn-sm btn-ghost btn-disabled">← Prev</button>"#.to_string()
    };
    let next_link = if page + 1 < total_pages {
        format!(r#"<a href="/audit?page={}{}" class="btn btn-sm btn-ghost">Next →</a>"#, page + 1, base_qs)
    } else {
        r#"<button class="btn btn-sm btn-ghost btn-disabled">Next →</button>"#.to_string()
    };

    // ── Page chrome ─────────────────────────────────────────────────────
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("audit", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    let content = format!(
        r##"<div class="flex items-center justify-between mb-6 flex-wrap gap-2">
<div><h1 class="text-2xl font-bold">Audit Log</h1>
<p class="text-base-content/60 text-sm">Read-only view over the tamper-evident WORM ledger · {total} entries</p></div>
<div class="flex gap-2">
<a href="/audit?verify=1{base_qs}" class="btn btn-sm btn-outline">Verify integrity</a>
<a href="/audit?format=csv{base_qs}" class="btn btn-sm btn-primary">Export CSV</a>
</div>
</div>

{verify_banner}

<form method="get" action="/audit" class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 items-end">
<div class="form-control"><label class="label py-1"><span class="label-text text-xs">User</span></label>
<input name="user" value="{f_user}" class="input input-bordered input-sm" placeholder="username"/></div>
<div class="form-control"><label class="label py-1"><span class="label-text text-xs">Action</span></label>
<select name="action" class="select select-bordered select-sm">{action_options}</select></div>
<div class="form-control"><label class="label py-1"><span class="label-text text-xs">Resource type</span></label>
<input name="resource" value="{f_resource}" class="input input-bordered input-sm" placeholder="e.g. country"/></div>
<div class="form-control"><label class="label py-1"><span class="label-text text-xs">From</span></label>
<input name="from" type="date" value="{f_from}" class="input input-bordered input-sm"/></div>
<div class="form-control"><label class="label py-1"><span class="label-text text-xs">To</span></label>
<input name="to" type="date" value="{f_to}" class="input input-bordered input-sm"/></div>
</div>
<div class="flex gap-2 mt-3">
<button type="submit" class="btn btn-sm btn-primary">Apply</button>
<a href="/audit" class="btn btn-sm btn-ghost">Clear</a>
</div>
</div></form>

<div class="card bg-base-100 shadow"><div class="card-body p-0 overflow-x-auto">
<table class="table table-sm">
<thead><tr><th>Time (UTC)</th><th>User</th><th>Action</th><th>Resource</th><th>Result</th><th>IP</th><th>Chain</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div></div>

<div class="flex items-center justify-between mt-4">
<span class="text-sm text-base-content/60">Page {page_disp} of {total_pages}</span>
<div class="flex gap-2">{prev}{next}</div>
</div>"##,
        total = total,
        base_qs = base_qs,
        verify_banner = verify_banner,
        f_user = html_escape(f_user.as_deref().unwrap_or("")),
        f_resource = html_escape(f_resource.as_deref().unwrap_or("")),
        f_from = html_escape(f_from.as_deref().unwrap_or("")),
        f_to = html_escape(f_to.as_deref().unwrap_or("")),
        action_options = action_options,
        rows = rows_html,
        page_disp = page + 1,
        total_pages = total_pages,
        prev = prev_link,
        next = next_link,
    );

    let html = format!(
        r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Audit Log - Remicle</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">{content}</main></div></body></html>"#,
        sidebar = sidebar,
        content = content,
    );
    Html(html).into_response()
}

// Activity Types Management
#[derive(Debug, serde::Deserialize)]
struct ActivityTypeForm {
    name: String,
    icon: Option<String>,
    color: Option<String>,
    default_days: Option<i32>,
    sequence: Option<i32>,
}

// ─── Custom Fields (Initiative #2 admin UI) ──────────────────────────────
#[derive(serde::Deserialize)]
struct CustomFieldForm {
    model: String,
    name: String,
    label: String,
    field_type: String,
    #[serde(default)]
    options: Option<String>,
    #[serde(default)]
    related_model: Option<String>,
    #[serde(default)]
    position_after: Option<String>,
    #[serde(default)]
    help: Option<String>,
}

#[derive(serde::Deserialize)]
struct CustomFieldDeleteForm {
    model: String,
    name: String,
}

/// Render the Custom Fields settings page, optionally with an error banner.
async fn render_custom_fields_page(db: &sqlx::PgPool, username: &str, error: Option<&str>) -> String {
    use vortex_framework::ui::html_escape;

    // Models available to extend (registered in ir_model, now derive-sourced).
    let models = sqlx::query("SELECT name, display_name FROM ir_model WHERE is_active = true ORDER BY display_name")
        .fetch_all(db)
        .await
        .unwrap_or_default();
    let mut model_options = String::new();
    for m in &models {
        let name: String = m.get("name");
        let label: String = m.get("display_name");
        model_options.push_str(&format!(
            r#"<option value="{}">{} ({})</option>"#,
            html_escape(&name), html_escape(&label), html_escape(&name)
        ));
    }

    // Built-in fields per model, for the "Position" dropdown (anchor a custom
    // field after one of them). Serialized as JSON for the client to filter by
    // the selected model. Only non-custom fields are offered as anchors.
    let field_rows = sqlx::query(
        "SELECT m.name AS model, f.name AS fname, f.display_name AS flabel \
         FROM ir_model_field f JOIN ir_model m ON m.id = f.model_id \
         WHERE f.is_custom = false AND m.is_active = true \
         ORDER BY m.name, f.sequence, f.name",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut mf: std::collections::BTreeMap<String, Vec<serde_json::Value>> = std::collections::BTreeMap::new();
    for r in &field_rows {
        let model: String = r.get("model");
        let fname: String = r.get("fname");
        let flabel: String = r.get("flabel");
        mf.entry(model).or_default().push(serde_json::json!([fname, flabel]));
    }
    let model_fields_json = serde_json::to_string(
        &serde_json::Value::Object(mf.into_iter().map(|(k, v)| (k, serde_json::Value::Array(v))).collect()),
    )
    .unwrap_or_else(|_| "{}".to_string());

    // Existing custom fields across all models.
    let fields = vortex_framework::custom_fields::list_all(db).await;
    let mut rows_html = String::new();
    for (model, model_label, f) in &fields {
        // "Options" column shows selection values, or the link target for a reference.
        let opts = if f.field_type == "many2one" {
            match &f.related_model {
                Some(t) => format!(r#"<span class="opacity-70">→ <code class="text-xs">{}</code></span>"#, html_escape(t)),
                None => String::from("<span class=\"opacity-40\">—</span>"),
            }
        } else if f.selection_options.is_empty() {
            String::from("<span class=\"opacity-40\">—</span>")
        } else {
            html_escape(&f.selection_options.join(", "))
        };
        // Reorder controls: swap sequence with the neighbouring custom field.
        let reorder = format!(
            r##"<form method="post" action="/settings/custom-fields/reorder" class="inline">
                    <input type="hidden" name="model" value="{model}"/>
                    <input type="hidden" name="name" value="{name}"/>
                    <input type="hidden" name="direction" value="up"/>
                    <button type="submit" class="btn btn-ghost btn-xs" title="Move up">↑</button>
                </form>
                <form method="post" action="/settings/custom-fields/reorder" class="inline">
                    <input type="hidden" name="model" value="{model}"/>
                    <input type="hidden" name="name" value="{name}"/>
                    <input type="hidden" name="direction" value="down"/>
                    <button type="submit" class="btn btn-ghost btn-xs" title="Move down">↓</button>
                </form>"##,
            model = html_escape(model),
            name = html_escape(&f.name),
        );
        // Edit opens the shared modal pre-filled from these data-* attributes.
        let edit_btn = format!(
            r#"<button type="button" class="btn btn-ghost btn-xs"
                data-model="{model}" data-name="{name}" data-label="{label}" data-type="{ftype}"
                data-options="{opts_raw}" data-related="{related}" data-position="{position}" data-help="{help}"
                onclick="cfEdit(this)">Edit</button>"#,
            model = html_escape(model),
            name = html_escape(&f.name),
            label = html_escape(&f.label),
            ftype = html_escape(&f.field_type),
            opts_raw = html_escape(&f.selection_options.join(", ")),
            related = html_escape(f.related_model.as_deref().unwrap_or("")),
            position = html_escape(f.position_after.as_deref().unwrap_or("")),
            help = html_escape(f.help.as_deref().unwrap_or("")),
        );
        rows_html.push_str(&format!(
            r##"<tr>
                <td>{model_label} <code class="text-xs opacity-60">{model}</code></td>
                <td><code class="text-sm">{name}</code></td>
                <td>{label}</td>
                <td><span class="badge badge-ghost">{ftype}</span></td>
                <td class="text-sm">{opts}</td>
                <td class="text-right whitespace-nowrap">
                    {reorder}
                    {edit_btn}
                    <form method="post" action="/settings/custom-fields/delete" onsubmit="return confirm('Delete custom field {name}? Stored values are kept but hidden.');" class="inline">
                        <input type="hidden" name="model" value="{model}"/>
                        <input type="hidden" name="name" value="{name}"/>
                        <button type="submit" class="btn btn-ghost btn-xs text-error">Delete</button>
                    </form>
                </td>
            </tr>"##,
            model_label = html_escape(model_label),
            model = html_escape(model),
            name = html_escape(&f.name),
            label = html_escape(&f.label),
            ftype = html_escape(&f.field_type),
            opts = opts,
            reorder = reorder,
            edit_btn = edit_btn,
        ));
    }
    if rows_html.is_empty() {
        rows_html.push_str(r#"<tr><td colspan="6" class="text-center opacity-60 py-8">No custom fields yet. Add one to extend any model.</td></tr>"#);
    }

    let mut type_options = String::new();
    for (code, label) in vortex_framework::custom_fields::CUSTOM_FIELD_TYPES {
        type_options.push_str(&format!(r#"<option value="{code}">{label}</option>"#));
    }

    let error_banner = error
        .map(|e| format!(r#"<div class="alert alert-error mb-4"><span>{}</span></div>"#, html_escape(e)))
        .unwrap_or_default();

    format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Custom Fields - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
    <link href="/static/vortex.css?v=18" rel="stylesheet"/>
    <script src="/static/vortex.js?v=18" defer></script>
    <script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{username}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Custom Fields</h1>
                <p class="text-base-content/60">Add your own fields to any model. They appear on the record form automatically — no code, no deploy.</p>
            </div>
            <button class="btn btn-primary" onclick="cfNew()">+ New Custom Field</button>
        </div>
        {error_banner}
        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table class="table">
                    <thead><tr><th>Model</th><th>Field</th><th>Label</th><th>Type</th><th>Options</th><th></th></tr></thead>
                    <tbody>{rows_html}</tbody>
                </table>
            </div>
        </div>
        <div class="mt-4"><a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a></div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4" id="cf-modal-title">New Custom Field</h3>
            <form method="post" action="/settings/custom-fields">
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Model</span></label>
                    <select name="model" id="cf-model" class="select select-bordered" required onchange="cfModelChange()">{model_options}</select>
                    <input type="hidden" id="cf-model-hidden"/>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Field name</span></label>
                        <input type="text" name="name" id="cf-name" class="input input-bordered font-mono" value="x_" placeholder="x_priority" required/>
                        <span class="label-text-alt opacity-60 mt-1" id="cf-name-hint">lowercase, starts with x_</span>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Label</span></label>
                        <input type="text" name="label" id="cf-label" class="input input-bordered" placeholder="Priority" required/>
                    </div>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Type</span></label>
                        <select name="field_type" id="cf-type" class="select select-bordered" onchange="cfToggle()">{type_options}</select>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Position</span></label>
                        <select name="position_after" id="cf-position" class="select select-bordered"></select>
                        <span class="label-text-alt opacity-60 mt-1">where it appears on the form</span>
                    </div>
                    <div class="form-control mb-3" id="cf-options-wrap">
                        <label class="label"><span class="label-text">Options</span></label>
                        <input type="text" name="options" id="cf-options" class="input input-bordered" placeholder="low, medium, high"/>
                        <span class="label-text-alt opacity-60 mt-1">comma-separated · Selection only</span>
                    </div>
                    <div class="form-control mb-3" id="cf-target-wrap" style="display:none">
                        <label class="label"><span class="label-text">Target model</span></label>
                        <select name="related_model" id="cf-related" class="select select-bordered">{model_options}</select>
                        <span class="label-text-alt opacity-60 mt-1">the model this field links to · Reference only</span>
                    </div>
                </div>
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Help text (optional)</span></label>
                    <input type="text" name="help" id="cf-help" class="input input-bordered" placeholder="Shown under the field"/>
                </div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary" id="cf-submit">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
    <script>
    var CF_MODEL_FIELDS = {model_fields_json};
    // Show/hide the Options (selection) and Target model (reference) inputs.
    function cfToggle() {{
        var t = document.getElementById('cf-type').value;
        document.getElementById('cf-options-wrap').style.display = (t === 'selection') ? '' : 'none';
        document.getElementById('cf-target-wrap').style.display  = (t === 'many2one') ? '' : 'none';
    }}
    // Repopulate the Position dropdown from the selected model's built-in fields.
    function cfPositions(model, selected) {{
        var sel = document.getElementById('cf-position');
        sel.innerHTML = '<option value="">Bottom (Custom Fields section)</option>';
        var list = CF_MODEL_FIELDS[model] || [];
        for (var i = 0; i < list.length; i++) {{
            var o = document.createElement('option');
            o.value = list[i][0];
            o.textContent = 'After: ' + list[i][1];
            if (list[i][0] === selected) o.selected = true;
            sel.appendChild(o);
        }}
    }}
    function cfModelChange() {{
        cfPositions(document.getElementById('cf-model').value, '');
    }}
    // Open the modal in create mode: editable name, blank fields.
    function cfNew() {{
        document.getElementById('cf-modal-title').textContent = 'New Custom Field';
        document.getElementById('cf-submit').textContent = 'Create';
        var model = document.getElementById('cf-model');
        model.disabled = false;
        document.getElementById('cf-model-hidden').removeAttribute('name');
        var name = document.getElementById('cf-name');
        name.readOnly = false; name.value = 'x_';
        document.getElementById('cf-name-hint').style.display = '';
        document.getElementById('cf-label').value = '';
        document.getElementById('cf-type').value = 'string';
        document.getElementById('cf-options').value = '';
        document.getElementById('cf-help').value = '';
        cfPositions(model.value, '');
        cfToggle();
        document.getElementById('create-modal').showModal();
    }}
    // Open the modal in edit mode: model + name locked (they key the record).
    function cfEdit(btn) {{
        var d = btn.dataset;
        document.getElementById('cf-modal-title').textContent = 'Edit Custom Field';
        document.getElementById('cf-submit').textContent = 'Save changes';
        var model = document.getElementById('cf-model');
        model.value = d.model; model.disabled = true;
        var hidden = document.getElementById('cf-model-hidden');
        hidden.setAttribute('name', 'model'); hidden.value = d.model;
        var name = document.getElementById('cf-name');
        name.value = d.name; name.readOnly = true;
        document.getElementById('cf-name-hint').style.display = 'none';
        document.getElementById('cf-label').value = d.label;
        document.getElementById('cf-type').value = d.type;
        document.getElementById('cf-options').value = d.options || '';
        document.getElementById('cf-related').value = d.related || '';
        document.getElementById('cf-help').value = d.help || '';
        cfPositions(d.model, d.position || '');
        cfToggle();
        document.getElementById('create-modal').showModal();
    }}
    cfModelChange();
    </script>
</body>
</html>"##
    )
}

async fn custom_fields_list(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if !user.is_system_admin() && !user.has_role("Administrator") {
        return Redirect::to("/settings").into_response();
    }
    Html(render_custom_fields_page(&db, &user.username, None).await).into_response()
}

async fn custom_field_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<CustomFieldForm>,
) -> Response {
    if !user.is_system_admin() && !user.has_role("Administrator") {
        return Redirect::to("/settings").into_response();
    }
    let options: Vec<String> = form
        .options
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let help = form.help.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let related_model = form.related_model.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let position_after = form.position_after.as_deref().map(str::trim).filter(|s| !s.is_empty());

    match vortex_framework::custom_fields::add(
        &db, form.model.trim(), form.name.trim(), form.label.trim(),
        form.field_type.trim(), &options, related_model, position_after, help,
    ).await {
        Ok(()) => {
            let audit = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
                .with_user(vortex_common::UserId(user.id))
                .with_username(&user.username)
                .with_database(&db_ctx.db_name)
                .with_resource("custom_field", format!("{}.{}", form.model.trim(), form.name.trim()))
                .with_details(serde_json::json!({
                    "action": "add", "type": form.field_type.trim(), "label": form.label.trim(),
                }));
            let _ = state.audit.log(audit).await;
            Redirect::to("/settings/custom-fields").into_response()
        }
        Err(e) => Html(render_custom_fields_page(&db, &user.username, Some(&e)).await).into_response(),
    }
}

async fn custom_field_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<CustomFieldDeleteForm>,
) -> Response {
    if !user.is_system_admin() && !user.has_role("Administrator") {
        return Redirect::to("/settings").into_response();
    }
    if let Err(e) = vortex_framework::custom_fields::delete(&db, form.model.trim(), form.name.trim()).await {
        return Html(render_custom_fields_page(&db, &user.username, Some(&e)).await).into_response();
    }
    let audit = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("custom_field", format!("{}.{}", form.model.trim(), form.name.trim()))
        .with_details(serde_json::json!({ "action": "delete" }));
    let _ = state.audit.log(audit).await;
    Redirect::to("/settings/custom-fields").into_response()
}

#[derive(serde::Deserialize)]
struct CustomFieldReorderForm {
    model: String,
    name: String,
    /// "up" moves the field earlier; anything else moves it later.
    direction: String,
}

/// POST /settings/custom-fields/reorder — move a custom field up or down within
/// its model's Custom Fields section (swaps sequence with its neighbour).
async fn custom_field_reorder(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<CustomFieldReorderForm>,
) -> Response {
    if !user.is_system_admin() && !user.has_role("Administrator") {
        return Redirect::to("/settings").into_response();
    }
    let _ = vortex_framework::custom_fields::move_field(
        &db, form.model.trim(), form.name.trim(), form.direction.trim() == "up",
    )
    .await;
    Redirect::to("/settings/custom-fields").into_response()
}

// ─── Automation Rules (Initiative #3 admin UI) ───────────────────────────
#[derive(serde::Deserialize)]
struct AutomationRuleForm {
    name: String,
    model: String,
    trigger: String,
    #[serde(default)]
    condition_field: Option<String>,
    #[serde(default)]
    condition_op: Option<String>,
    #[serde(default)]
    condition_value: Option<String>,
    action_field: String,
    #[serde(default)]
    action_value: Option<String>,
}

#[derive(serde::Deserialize)]
struct AutomationRuleDeleteForm {
    id: uuid::Uuid,
}

async fn render_automation_rules_page(db: &sqlx::PgPool, username: &str, error: Option<&str>) -> String {
    use vortex_framework::ui::html_escape;

    let models = sqlx::query("SELECT name, display_name FROM ir_model WHERE is_active = true ORDER BY display_name")
        .fetch_all(db).await.unwrap_or_default();
    let mut model_options = String::new();
    for m in &models {
        let name: String = m.get("name");
        let label: String = m.get("display_name");
        model_options.push_str(&format!(r#"<option value="{}">{} ({})</option>"#,
            html_escape(&name), html_escape(&label), html_escape(&name)));
    }
    // Convenience datalist of all registered field names.
    let field_rows = sqlx::query("SELECT DISTINCT name FROM ir_model_field WHERE is_custom = false ORDER BY name")
        .fetch_all(db).await.unwrap_or_default();
    let mut field_datalist = String::new();
    for f in &field_rows {
        let n: String = f.get("name");
        field_datalist.push_str(&format!(r#"<option value="{}"></option>"#, html_escape(&n)));
    }

    let mut trigger_options = String::new();
    for (code, label) in vortex_framework::automation::TRIGGERS {
        trigger_options.push_str(&format!(r#"<option value="{code}">{label}</option>"#));
    }
    let mut op_options = String::from(r#"<option value="">(no condition)</option>"#);
    for (code, label) in vortex_framework::automation::OPERATORS {
        op_options.push_str(&format!(r#"<option value="{code}">{label}</option>"#));
    }
    let op_label = |code: &str| vortex_framework::automation::OPERATORS.iter()
        .find(|(c, _)| *c == code).map(|(_, l)| *l).unwrap_or(code).to_string();
    let trig_label = |code: &str| vortex_framework::automation::TRIGGERS.iter()
        .find(|(c, _)| *c == code).map(|(_, l)| *l).unwrap_or(code).to_string();

    let rules = vortex_framework::automation::list_all(db).await;
    let mut rows_html = String::new();
    for r in &rules {
        let condition = match (&r.condition_field, &r.condition_op) {
            (Some(f), Some(op)) => format!("<code>{}</code> {} <code>{}</code>",
                html_escape(f), html_escape(&op_label(op)), html_escape(r.condition_value.as_deref().unwrap_or(""))),
            _ => "<span class=\"opacity-40\">always</span>".to_string(),
        };
        let action = format!("set <code>{}</code> = <code>{}</code>",
            html_escape(&r.action_field), html_escape(r.action_value.as_deref().unwrap_or("∅")));
        rows_html.push_str(&format!(
            r##"<tr>
                <td>{name}</td>
                <td><code class="text-xs">{model}</code> {trig}</td>
                <td class="text-sm">{condition}</td>
                <td class="text-sm">{action}</td>
                <td class="text-right"><form method="post" action="/settings/automation-rules/delete" onsubmit="return confirm('Delete rule {name}?');" class="inline"><input type="hidden" name="id" value="{id}"/><button class="btn btn-ghost btn-xs text-error">Delete</button></form></td>
            </tr>"##,
            name = html_escape(&r.name), model = html_escape(&r.model_name),
            trig = html_escape(&trig_label(&r.trigger_event)),
            condition = condition, action = action, id = r.id,
        ));
    }
    if rows_html.is_empty() {
        rows_html.push_str(r#"<tr><td colspan="5" class="text-center opacity-60 py-8">No automation rules yet. Add one to react to record changes automatically.</td></tr>"#);
    }

    let error_banner = error.map(|e| format!(r#"<div class="alert alert-error mb-4"><span>{}</span></div>"#, html_escape(e))).unwrap_or_default();

    format!(r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Automation Rules - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
    <link href="/static/vortex.css?v=18" rel="stylesheet"/>
    <script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg"><div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div><div class="flex-none"><span class="text-sm">@{username}</span></div></div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div><h1 class="text-2xl font-bold">Automation Rules</h1>
            <p class="text-base-content/60">When a record changes and matches a condition, run an action automatically — no code.</p></div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Rule</button>
        </div>
        {error_banner}
        <div class="card bg-base-100 shadow"><div class="card-body p-0">
            <table class="table"><thead><tr><th>Name</th><th>When</th><th>Condition</th><th>Action</th><th></th></tr></thead>
            <tbody>{rows_html}</tbody></table>
        </div></div>
        <div class="mt-4"><a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a></div>
    </div>
    <datalist id="field-list">{field_datalist}</datalist>
    <dialog id="create-modal" class="modal"><div class="modal-box max-w-2xl">
        <h3 class="font-bold text-lg mb-4">New Automation Rule</h3>
        <form method="post" action="/settings/automation-rules">
            <div class="form-control mb-3"><label class="label"><span class="label-text">Rule name</span></label>
                <input type="text" name="name" class="input input-bordered" placeholder="Flag VIP customers" required/></div>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div class="form-control mb-3"><label class="label"><span class="label-text">When this model…</span></label>
                    <select name="model" class="select select-bordered" required>{model_options}</select></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">…is</span></label>
                    <select name="trigger" class="select select-bordered">{trigger_options}</select></div>
            </div>
            <div class="divider text-xs opacity-60">CONDITION (optional)</div>
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Field</span></label>
                    <input type="text" name="condition_field" list="field-list" class="input input-bordered font-mono" placeholder="contact_type"/></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Operator</span></label>
                    <select name="condition_op" class="select select-bordered">{op_options}</select></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Value</span></label>
                    <input type="text" name="condition_value" class="input input-bordered" placeholder="customer"/></div>
            </div>
            <div class="divider text-xs opacity-60">ACTION</div>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Set field</span></label>
                    <input type="text" name="action_field" list="field-list" class="input input-bordered font-mono" placeholder="city" required/></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">To value</span></label>
                    <input type="text" name="action_value" class="input input-bordered" placeholder="VIP"/></div>
            </div>
            <div class="modal-action">
                <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                <button type="submit" class="btn btn-primary">Create rule</button>
            </div>
        </form>
    </div><form method="dialog" class="modal-backdrop"><button>close</button></form></dialog>
</body></html>"##)
}

async fn automation_rules_list(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if !user.is_admin() {
        return Redirect::to("/settings").into_response();
    }
    Html(render_automation_rules_page(&db, &user.username, None).await).into_response()
}

async fn automation_rule_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<AutomationRuleForm>,
) -> Response {
    if !user.is_admin() {
        return Redirect::to("/settings").into_response();
    }
    let cond_field = form.condition_field.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let cond_op = form.condition_op.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let cond_val = form.condition_value.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let action_val = form.action_value.as_deref().map(str::trim).filter(|s| !s.is_empty());

    match vortex_framework::automation::create(
        &db, form.name.trim(), form.model.trim(), form.trigger.trim(),
        cond_field, cond_op, cond_val, form.action_field.trim(), action_val, Some(user.id),
    ).await {
        Ok(()) => {
            let audit = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
                .with_user(vortex_common::UserId(user.id))
                .with_username(&user.username)
                .with_database(&db_ctx.db_name)
                .with_resource("automation_rule", format!("{}:{}", form.model.trim(), form.name.trim()))
                .with_details(serde_json::json!({"action": "add", "trigger": form.trigger.trim()}));
            let _ = state.audit.log(audit).await;
            Redirect::to("/settings/automation-rules").into_response()
        }
        Err(e) => Html(render_automation_rules_page(&db, &user.username, Some(&e)).await).into_response(),
    }
}

async fn automation_rule_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<AutomationRuleDeleteForm>,
) -> Response {
    if !user.is_admin() {
        return Redirect::to("/settings").into_response();
    }
    if let Err(e) = vortex_framework::automation::delete(&db, form.id).await {
        return Html(render_automation_rules_page(&db, &user.username, Some(&e)).await).into_response();
    }
    let audit = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("automation_rule", form.id.to_string())
        .with_details(serde_json::json!({"action": "delete"}));
    let _ = state.audit.log(audit).await;
    Redirect::to("/settings/automation-rules").into_response()
}

// ─── Computed Fields (Initiative #5 admin UI) ────────────────────────────
#[derive(serde::Deserialize)]
struct ComputedFieldForm {
    model: String,
    name: String,
    label: String,
    kind: String,
    expr: String,
    #[serde(default)]
    help: Option<String>,
}

async fn render_computed_fields_page(db: &sqlx::PgPool, username: &str, error: Option<&str>) -> String {
    use vortex_framework::ui::html_escape;

    let models = sqlx::query("SELECT name, display_name FROM ir_model WHERE is_active = true ORDER BY display_name")
        .fetch_all(db).await.unwrap_or_default();
    let mut model_options = String::new();
    for m in &models {
        let name: String = m.get("name");
        let label: String = m.get("display_name");
        model_options.push_str(&format!(r#"<option value="{}">{} ({})</option>"#,
            html_escape(&name), html_escape(&label), html_escape(&name)));
    }
    let mut kind_options = String::new();
    for (code, label) in vortex_framework::computed_fields::COMPUTE_KINDS {
        kind_options.push_str(&format!(r#"<option value="{code}">{label}</option>"#));
    }

    let fields = vortex_framework::computed_fields::list_all(db).await;
    let mut rows_html = String::new();
    for (model, model_label, f) in &fields {
        let kind_badge = if f.kind == "related" { "related" } else { "formula" };
        rows_html.push_str(&format!(
            r##"<tr>
                <td>{model_label} <code class="text-xs opacity-60">{model}</code></td>
                <td><code class="text-sm">{name}</code></td>
                <td>{label}</td>
                <td><span class="badge badge-ghost">{kind}</span></td>
                <td><code class="text-sm">{expr}</code></td>
                <td class="text-right">
                    <form method="post" action="/settings/computed-fields/delete" onsubmit="return confirm('Delete computed field {name}?');" class="inline">
                        <input type="hidden" name="model" value="{model}"/>
                        <input type="hidden" name="name" value="{name}"/>
                        <button class="btn btn-ghost btn-xs text-error">Delete</button>
                    </form>
                </td>
            </tr>"##,
            model_label = html_escape(model_label), model = html_escape(model),
            name = html_escape(&f.name), label = html_escape(&f.label),
            kind = kind_badge, expr = html_escape(&f.expr),
        ));
    }
    if rows_html.is_empty() {
        rows_html.push_str(r#"<tr><td colspan="6" class="text-center opacity-60 py-8">No computed fields yet. Add one to derive a value automatically.</td></tr>"#);
    }

    let error_banner = error.map(|e| format!(r#"<div class="alert alert-error mb-4"><span>{}</span></div>"#, html_escape(e))).unwrap_or_default();

    format!(r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Computed Fields - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
    <link href="/static/vortex.css?v=18" rel="stylesheet"/>
    <script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg"><div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div><div class="flex-none"><span class="text-sm">@{username}</span></div></div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div><h1 class="text-2xl font-bold">Computed Fields</h1>
            <p class="text-base-content/60">Derive a read-only value from a formula over this record's number fields, or pull one across a link. Recomputed on every save — no code.</p></div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Computed Field</button>
        </div>
        {error_banner}
        <div class="card bg-base-100 shadow"><div class="card-body p-0">
            <table class="table"><thead><tr><th>Model</th><th>Field</th><th>Label</th><th>Kind</th><th>Definition</th><th></th></tr></thead>
            <tbody>{rows_html}</tbody></table>
        </div></div>
        <div class="mt-4"><a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a></div>
    </div>
    <dialog id="create-modal" class="modal"><div class="modal-box max-w-2xl">
        <h3 class="font-bold text-lg mb-4">New Computed Field</h3>
        <form method="post" action="/settings/computed-fields">
            <div class="form-control mb-3"><label class="label"><span class="label-text">Model</span></label>
                <select name="model" class="select select-bordered" required>{model_options}</select></div>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Field name</span></label>
                    <input type="text" name="name" class="input input-bordered font-mono" value="x_" placeholder="x_line_total" required/>
                    <span class="label-text-alt opacity-60 mt-1">lowercase, starts with x_</span></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Label</span></label>
                    <input type="text" name="label" class="input input-bordered" placeholder="Line Total" required/></div>
            </div>
            <div class="form-control mb-3"><label class="label"><span class="label-text">Kind</span></label>
                <select name="kind" class="select select-bordered">{kind_options}</select></div>
            <div class="form-control mb-3"><label class="label"><span class="label-text">Definition</span></label>
                <input type="text" name="expr" class="input input-bordered font-mono" placeholder="qty * unit_price   —or—   partner_id.email" required/>
                <span class="label-text-alt opacity-60 mt-1">Formula: arithmetic on number fields (+ - * / and parentheses). Related: link_field.target_field</span></div>
            <div class="form-control mb-3"><label class="label"><span class="label-text">Help text (optional)</span></label>
                <input type="text" name="help" class="input input-bordered" placeholder="Shown under the field"/></div>
            <div class="modal-action">
                <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                <button type="submit" class="btn btn-primary">Create</button>
            </div>
        </form>
    </div><form method="dialog" class="modal-backdrop"><button>close</button></form></dialog>
</body></html>"##)
}

async fn computed_fields_list(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if !user.is_system_admin() && !user.has_role("Administrator") {
        return Redirect::to("/settings").into_response();
    }
    Html(render_computed_fields_page(&db, &user.username, None).await).into_response()
}

async fn computed_field_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<ComputedFieldForm>,
) -> Response {
    if !user.is_system_admin() && !user.has_role("Administrator") {
        return Redirect::to("/settings").into_response();
    }
    let help = form.help.as_deref().map(str::trim).filter(|s| !s.is_empty());
    match vortex_framework::computed_fields::add(
        &db, form.model.trim(), form.name.trim(), form.label.trim(),
        form.kind.trim(), form.expr.trim(), help,
    ).await {
        Ok(()) => {
            let audit = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
                .with_user(vortex_common::UserId(user.id))
                .with_username(&user.username)
                .with_database(&db_ctx.db_name)
                .with_resource("computed_field", format!("{}.{}", form.model.trim(), form.name.trim()))
                .with_details(serde_json::json!({"action": "add", "kind": form.kind.trim(), "expr": form.expr.trim()}));
            let _ = state.audit.log(audit).await;
            Redirect::to("/settings/computed-fields").into_response()
        }
        Err(e) => Html(render_computed_fields_page(&db, &user.username, Some(&e)).await).into_response(),
    }
}

async fn computed_field_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<CustomFieldDeleteForm>,
) -> Response {
    if !user.is_system_admin() && !user.has_role("Administrator") {
        return Redirect::to("/settings").into_response();
    }
    if let Err(e) = vortex_framework::computed_fields::delete(&db, form.model.trim(), form.name.trim()).await {
        return Html(render_computed_fields_page(&db, &user.username, Some(&e)).await).into_response();
    }
    let audit = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("computed_field", format!("{}.{}", form.model.trim(), form.name.trim()))
        .with_details(serde_json::json!({"action": "delete"}));
    let _ = state.audit.log(audit).await;
    Redirect::to("/settings/computed-fields").into_response()
}

// ─── Dashboards (Initiative #4) ──────────────────────────────────────────
#[derive(serde::Deserialize)]
struct DashboardForm {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    shared: Option<String>,
}

#[derive(serde::Deserialize)]
struct WidgetForm {
    title: String,
    widget_type: String,
    model: String,
    #[serde(default)]
    measure_field: Option<String>,
    aggregate: String,
    #[serde(default)]
    group_field: Option<String>,
    #[serde(default)]
    filter_field: Option<String>,
    #[serde(default)]
    filter_op: Option<String>,
    #[serde(default)]
    filter_value: Option<String>,
    #[serde(default)]
    col_span: Option<i32>,
}

/// The shared page chrome for the dashboards views — the full app shell with
/// the host sidebar, so Dashboards feels like a first-class section (matching
/// Reports).
fn dashboard_full_page(sidebar: &str, title: &str, body: &str) -> String {
    format!(r##"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><title>{title} - Remicle</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0"><link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200"><div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}<main class="flex-1 p-4 lg:p-6 min-w-0">{body}</main></div></body></html>"##,
        title = vortex_framework::ui::html_escape(title), sidebar = sidebar, body = body)
}

async fn dashboards_index(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    use vortex_framework::ui::html_escape;
    let boards = vortex_framework::dashboards::list_visible(&db, user.id, user.is_admin()).await;
    let mut cards = String::new();
    for b in &boards {
        let shared = if b.is_shared { r#"<span class="badge badge-sm badge-ghost">shared</span>"# } else { "" };
        cards.push_str(&format!(
            r##"<a href="/dashboards/{id}" class="card bg-base-100 shadow transition-all hover:shadow-md">
                <div class="card-body p-5"><div class="flex items-center gap-2"><h3 class="card-title text-lg">{name}</h3>{shared}</div>
                <p class="text-base-content/60 text-sm">{desc}</p></div></a>"##,
            id = b.id, name = html_escape(&b.name), shared = shared,
            desc = html_escape(b.description.as_deref().unwrap_or("")),
        ));
    }
    if cards.is_empty() {
        cards.push_str(r#"<div class="col-span-full text-center opacity-60 py-12">No dashboards yet. Create one to get started.</div>"#);
    }

    let body = format!(r##"
        <div class="flex justify-between items-center mb-6">
            <div><h1 class="text-2xl font-bold">Dashboards</h1>
            <p class="text-base-content/60">Assemble KPI and breakdown widgets over any model — no code.</p></div>
            <button class="btn btn-primary" onclick="document.getElementById('new-dash').showModal();">+ New Dashboard</button>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">{cards}</div>
        <dialog id="new-dash" class="modal"><div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New Dashboard</h3>
            <form method="post" action="/dashboards">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" placeholder="Sales Overview" required/></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Description (optional)</span></label>
                    <input type="text" name="description" class="input input-bordered"/></div>
                <div class="form-control mb-3"><label class="label cursor-pointer justify-start gap-3">
                    <input type="checkbox" name="shared" class="checkbox checkbox-primary"/>
                    <span class="label-text">Share with everyone (otherwise only you see it)</span></label></div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('new-dash').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div><form method="dialog" class="modal-backdrop"><button>close</button></form></dialog>
    "##, cards = cards);
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("dashboards", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(dashboard_full_page(&sidebar, "Dashboards", &body)).into_response()
}

async fn dashboard_create(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<DashboardForm>,
) -> Response {
    let shared = matches!(form.shared.as_deref(), Some("on") | Some("true"));
    match vortex_framework::dashboards::create(
        &db, form.name.trim(), form.description.as_deref(), user.id, shared,
    ).await {
        Ok(id) => Redirect::to(&format!("/dashboards/{id}")).into_response(),
        Err(_) => Redirect::to("/dashboards").into_response(),
    }
}

async fn dashboard_view(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    use vortex_framework::ui::html_escape;
    let Some(board) = vortex_framework::dashboards::load(&db, id).await else {
        return Redirect::to("/dashboards").into_response();
    };
    let is_admin = user.is_admin();
    if !board.can_view(user.id, is_admin) {
        return Redirect::to("/dashboards").into_response();
    }
    let can_edit = board.can_edit(user.id, is_admin);

    // Widgets grid.
    let widgets = vortex_framework::dashboards::widgets_for(&db, id).await;
    let mut grid = String::new();
    for w in &widgets {
        grid.push_str(&vortex_framework::dashboards::render_widget(&db, w, can_edit).await);
    }
    if grid.is_empty() {
        grid.push_str(r#"<div class="col-span-full text-center opacity-60 py-12">No widgets yet.</div>"#);
    }

    // Edit controls (add widget + delete dashboard) only for editors.
    let (add_btn, edit_modal, delete_dash) = if can_edit {
        let models = sqlx::query("SELECT name, display_name FROM ir_model WHERE is_active = true ORDER BY display_name")
            .fetch_all(&db).await.unwrap_or_default();
        let mut model_options = String::new();
        for m in &models {
            let name: String = m.get("name");
            let label: String = m.get("display_name");
            model_options.push_str(&format!(r#"<option value="{}">{} ({})</option>"#,
                html_escape(&name), html_escape(&label), html_escape(&name)));
        }
        let field_rows = sqlx::query("SELECT DISTINCT name FROM ir_model_field WHERE is_custom = false ORDER BY name")
            .fetch_all(&db).await.unwrap_or_default();
        let mut field_datalist = String::new();
        for f in &field_rows {
            let n: String = f.get("name");
            field_datalist.push_str(&format!(r#"<option value="{}"></option>"#, html_escape(&n)));
        }
        let mut agg_options = String::new();
        for (code, label) in vortex_framework::dashboards::AGGREGATES {
            agg_options.push_str(&format!(r#"<option value="{code}">{label}</option>"#));
        }
        let mut type_options = String::new();
        for (code, label) in vortex_framework::dashboards::WIDGET_TYPES {
            type_options.push_str(&format!(r#"<option value="{code}">{label}</option>"#));
        }
        let mut op_options = String::from(r#"<option value="">(no filter)</option>"#);
        for (code, label) in vortex_framework::dashboards::FILTER_OPS {
            op_options.push_str(&format!(r#"<option value="{code}">{label}</option>"#));
        }
        let add = r#"<button class="btn btn-primary btn-sm" onclick="document.getElementById('add-widget').showModal();">+ Add Widget</button>"#.to_string();
        let modal = format!(r##"<datalist id="field-list">{field_datalist}</datalist>
        <dialog id="add-widget" class="modal"><div class="modal-box max-w-2xl">
            <h3 class="font-bold text-lg mb-4">Add Widget</h3>
            <form method="post" action="/dashboards/{id}/widget">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Title</span></label>
                    <input type="text" name="title" class="input input-bordered" placeholder="Total revenue" required/></div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Type</span></label>
                        <select name="widget_type" class="select select-bordered">{type_options}</select></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Model</span></label>
                        <select name="model" class="select select-bordered" required>{model_options}</select></div>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Measure</span></label>
                        <select name="aggregate" class="select select-bordered">{agg_options}</select></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Number field</span></label>
                        <input type="text" name="measure_field" list="field-list" class="input input-bordered font-mono" placeholder="(blank for Count)"/></div>
                </div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Break down by (Bars only)</span></label>
                    <input type="text" name="group_field" list="field-list" class="input input-bordered font-mono" placeholder="contact_type"/></div>
                <div class="divider text-xs opacity-60">FILTER (optional)</div>
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Field</span></label>
                        <input type="text" name="filter_field" list="field-list" class="input input-bordered font-mono"/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Operator</span></label>
                        <select name="filter_op" class="select select-bordered">{op_options}</select></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Value</span></label>
                        <input type="text" name="filter_value" class="input input-bordered"/></div>
                </div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Width</span></label>
                    <select name="col_span" class="select select-bordered">
                        <option value="1">Small (1 column)</option><option value="2">Medium (2 columns)</option><option value="3">Full width</option>
                    </select></div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('add-widget').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add</button>
                </div>
            </form>
        </div><form method="dialog" class="modal-backdrop"><button>close</button></form></dialog>"##);
        let del = format!(r#"<form method="post" action="/dashboards/{id}/delete" onsubmit="return confirm('Delete this dashboard and all its widgets?');" class="inline">
            <button class="btn btn-ghost btn-sm text-error">Delete dashboard</button></form>"#);
        (add, modal, del)
    } else {
        (String::new(), String::new(), String::new())
    };

    let body = format!(r##"
        <div class="flex flex-wrap justify-between items-center gap-2 mb-6">
            <div><a href="/dashboards" class="text-sm opacity-60 hover:underline">← All dashboards</a>
            <h1 class="text-2xl font-bold">{name}</h1>
            <p class="text-base-content/60">{desc}</p></div>
            <div class="flex gap-2">{add_btn}{delete_dash}</div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">{grid}</div>
        {edit_modal}
    "##,
        name = html_escape(&board.name),
        desc = html_escape(board.description.as_deref().unwrap_or("")),
        add_btn = add_btn, delete_dash = delete_dash, grid = grid, edit_modal = edit_modal);
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("dashboards", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(dashboard_full_page(&sidebar, &board.name, &body)).into_response()
}

async fn dashboard_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let Some(board) = vortex_framework::dashboards::load(&db, id).await else {
        return Redirect::to("/dashboards").into_response();
    };
    if !board.can_edit(user.id, user.is_admin()) {
        return Redirect::to("/dashboards").into_response();
    }
    let _ = vortex_framework::dashboards::delete(&db, id).await;
    let audit = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("dashboard", id.to_string())
        .with_details(serde_json::json!({"action": "delete"}));
    let _ = state.audit.log(audit).await;
    Redirect::to("/dashboards").into_response()
}

async fn dashboard_widget_create(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<WidgetForm>,
) -> Response {
    let dest = format!("/dashboards/{id}");
    let Some(board) = vortex_framework::dashboards::load(&db, id).await else {
        return Redirect::to("/dashboards").into_response();
    };
    if !board.can_edit(user.id, user.is_admin()) {
        return Redirect::to(&dest).into_response();
    }
    let _ = vortex_framework::dashboards::add_widget(
        &db, id, form.title.trim(), form.widget_type.trim(), form.model.trim(),
        form.measure_field.as_deref(), form.aggregate.trim(),
        form.group_field.as_deref(), form.filter_field.as_deref(),
        form.filter_op.as_deref(), form.filter_value.as_deref(),
        form.col_span.unwrap_or(1),
    ).await;
    Redirect::to(&dest).into_response()
}

async fn dashboard_widget_delete(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Resolve the widget's dashboard and check edit rights before deleting.
    let dash_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT dashboard_id FROM dashboard_widget WHERE id = $1")
        .bind(id).fetch_optional(&db).await.ok().flatten();
    let Some(dash_id) = dash_id else {
        return Redirect::to("/dashboards").into_response();
    };
    let dest = format!("/dashboards/{dash_id}");
    if let Some(board) = vortex_framework::dashboards::load(&db, dash_id).await {
        if board.can_edit(user.id, user.is_admin()) {
            let _ = vortex_framework::dashboards::delete_widget(&db, id).await;
        }
    }
    Redirect::to(&dest).into_response()
}

async fn activity_types_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let types = sqlx::query(
        "SELECT id, name, icon, color, default_days, sequence FROM chatter_activity_types WHERE active = true ORDER BY sequence, name"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows_html = String::new();
    for t in &types {
        let id: uuid::Uuid = t.get("id");
        let name: String = t.get("name");
        let icon: String = t.get::<Option<String>, _>("icon").unwrap_or_else(|| "clock".to_string());
        let color: String = t.get::<Option<String>, _>("color").unwrap_or_else(|| "primary".to_string());
        let default_days: i32 = t.get::<Option<i32>, _>("default_days").unwrap_or(1);
        let sequence: i32 = t.get::<Option<i32>, _>("sequence").unwrap_or(10);

        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/activity-types/{}" class="link link-primary">{}</a></td>
                <td><code class="text-sm">{}</code></td>
                <td><span class="badge badge-{}">{}</span></td>
                <td>{} days</td>
                <td>{}</td>
            </tr>"##,
            id, name, icon, color, color, default_days, sequence
        ));
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Activity Types - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
    <script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Activity Types</h1>
                <p class="text-base-content/60">Configure activity types</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Activity Type</button>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Icon</th>
                            <th>Color</th>
                            <th>Default Days</th>
                            <th>Sequence</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4">
            <a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a>
        </div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New Activity Type</h3>
            <form method="post" action="/settings/activity-types">
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" placeholder="e.g., Follow Up" required/>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Icon</span></label>
                        <input type="text" name="icon" class="input input-bordered" value="clock" placeholder="clock"/>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Color</span></label>
                        <select name="color" class="select select-bordered">
                            <option value="primary">Primary</option>
                            <option value="secondary">Secondary</option>
                            <option value="accent">Accent</option>
                            <option value="info">Info</option>
                            <option value="success">Success</option>
                            <option value="warning">Warning</option>
                            <option value="error">Error</option>
                        </select>
                    </div>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Default Days</span></label>
                        <input type="number" name="default_days" class="input input-bordered" value="1" min="1"/>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Sequence</span></label>
                        <input type="number" name="sequence" class="input input-bordered" value="10" min="0"/>
                    </div>
                </div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user.username, rows_html
    );
    Html(html).into_response()
}

async fn activity_type_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<ActivityTypeForm>,
) -> Response {
    let company_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let id = uuid::Uuid::now_v7();
    let _ = sqlx::query(
        "INSERT INTO chatter_activity_types (id, name, icon, color, default_days, sequence, company_id, active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, true)"
    )
    .bind(id)
    .bind(form.name.trim())
    .bind(form.icon.as_deref().unwrap_or("clock"))
    .bind(form.color.as_deref().unwrap_or("primary"))
    .bind(form.default_days.unwrap_or(1))
    .bind(form.sequence.unwrap_or(10))
    .bind(company_id)
    .execute(&db)
    .await;

    Redirect::to("/settings/activity-types").into_response()
}

async fn activity_type_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let at = sqlx::query(
        "SELECT id, name, icon, color, default_days, sequence FROM chatter_activity_types WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(at) = at else {
        return Redirect::to("/settings/activity-types").into_response();
    };

    let name: String = at.get("name");
    let icon: String = at.get::<Option<String>, _>("icon").unwrap_or_else(|| "clock".to_string());
    let color: String = at.get::<Option<String>, _>("color").unwrap_or_else(|| "primary".to_string());
    let default_days: i32 = at.get::<Option<i32>, _>("default_days").unwrap_or(1);
    let sequence: i32 = at.get::<Option<i32>, _>("sequence").unwrap_or(10);

    // Build color options
    let colors = ["primary", "secondary", "accent", "info", "success", "warning", "error"];
    let color_options: String = colors.iter().map(|c| {
        let selected = if *c == color { " selected" } else { "" };
        format!(r#"<option value="{}"{}>{}  </option>"#, c, selected, c.chars().next().unwrap().to_uppercase().to_string() + &c[1..])
    }).collect();

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Activity Type</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
    <script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-2xl">
        <div class="mb-6">
            <a href="/settings/activity-types" class="btn btn-ghost btn-sm">← Back to Activity Types</a>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body">
                <h2 class="card-title">{}</h2>
                <p class="text-base-content/60 mb-4">Edit activity type settings</p>

                <form method="post" action="/settings/activity-types/{}">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Name</span></label>
                        <input type="text" name="name" class="input input-bordered" value="{}" required/>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Icon</span></label>
                            <input type="text" name="icon" class="input input-bordered" value="{}"/>
                        </div>
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Color</span></label>
                            <select name="color" class="select select-bordered">{}</select>
                        </div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Default Days</span></label>
                            <input type="number" name="default_days" class="input input-bordered" value="{}" min="1"/>
                        </div>
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Sequence</span></label>
                            <input type="number" name="sequence" class="input input-bordered" value="{}" min="0"/>
                        </div>
                    </div>
                    <div class="card-actions justify-between mt-4">
                        <form method="post" action="/settings/activity-types/{}/delete" class="inline">
                            <button type="submit" class="btn btn-error btn-outline" onclick="return confirm('Delete this activity type?');">Delete</button>
                        </form>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html>"##,
        name, user.username, name, id, name, icon, color_options, default_days, sequence, id
    );

    Html(html).into_response()
}

async fn activity_type_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<ActivityTypeForm>,
) -> Response {
    let _ = sqlx::query(
        "UPDATE chatter_activity_types SET name = $1, icon = $2, color = $3, default_days = $4, sequence = $5, updated_at = NOW() WHERE id = $6"
    )
    .bind(form.name.trim())
    .bind(form.icon.as_deref().unwrap_or("clock"))
    .bind(form.color.as_deref().unwrap_or("primary"))
    .bind(form.default_days.unwrap_or(1))
    .bind(form.sequence.unwrap_or(10))
    .bind(id)
    .execute(&db)
    .await;

    Redirect::to("/settings/activity-types").into_response()
}

async fn activity_type_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let _ = sqlx::query("UPDATE chatter_activity_types SET active = false WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await;

    Redirect::to("/settings/activity-types").into_response()
}

// ============================================================================
// Localization — Countries & States master data
//
// Address master data (countries/states) is *core* platform data: the
// tables live in core migrations and are consumed by any vertical that
// stores addresses (contacts, sales, HR, …). These pages let an operator
// maintain that list from Settings without touching SQL. Read-only access
// for forms is still served by /api/countries and /api/states/{id}.
// ============================================================================

#[derive(Debug, serde::Deserialize)]
struct CountryForm {
    code: String,
    name: String,
    alpha3: Option<String>,
    phone_code: Option<String>,
    currency_code: Option<String>,
    sequence: Option<i32>,
    active: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct StateForm {
    country_id: uuid::Uuid,
    code: String,
    name: String,
    active: Option<String>,
}

/// Minimal error page for a failed master-data write (e.g. a unique-code
/// collision). Keeps the operator from silently losing their input.
fn settings_write_error(back: &str, msg: &str) -> Response {
    let html = format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Error</title>
<link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head><body class="min-h-screen bg-base-200"><div class="container mx-auto p-6 max-w-xl">
<div class="alert alert-error mb-4"><span>{}</span></div>
<a href="{}" class="btn btn-ghost btn-sm">← Back</a>
</div></body></html>"##,
        html_escape(msg), back
    );
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}

/// Success flash page with a link back (mirrors `settings_write_error`).
fn settings_write_ok(back: &str, msg: &str) -> Response {
    let html = format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Done</title>
<link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head><body class="min-h-screen bg-base-200"><div class="container mx-auto p-6 max-w-xl">
<div class="alert alert-success mb-4"><span>{}</span></div>
<a href="{}" class="btn btn-ghost btn-sm">← Back</a>
</div></body></html>"##,
        html_escape(msg), back
    );
    Html(html).into_response()
}

// ── Countries ───────────────────────────────────────────────────────────────

async fn countries_list(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let countries = sqlx::query(
        "SELECT id, code, alpha3, name, phone_code, currency_code, sequence, active \
         FROM countries ORDER BY sequence, name"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows_html = String::new();
    for c in &countries {
        let id: uuid::Uuid = c.get("id");
        let code: String = c.get("code");
        let alpha3: Option<String> = c.get("alpha3");
        let name: String = c.get("name");
        let phone_code: Option<String> = c.get("phone_code");
        let currency_code: Option<String> = c.get("currency_code");
        let sequence: i32 = c.get::<Option<i32>, _>("sequence").unwrap_or(100);
        let active: bool = c.get::<Option<bool>, _>("active").unwrap_or(true);

        let status_badge = if active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else {
            r#"<span class="badge badge-warning badge-sm">Archived</span>"#
        };

        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/countries/{}" class="link link-primary">{}</a></td>
                <td><code class="text-sm">{}</code></td>
                <td><code class="text-sm">{}</code></td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>"##,
            id,
            html_escape(&name),
            html_escape(&code),
            html_escape(alpha3.as_deref().unwrap_or("—")),
            html_escape(phone_code.as_deref().unwrap_or("—")),
            html_escape(currency_code.as_deref().unwrap_or("—")),
            sequence,
            status_badge,
        ));
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Countries - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{user}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Countries</h1>
                <p class="text-base-content/60">Maintain the country master list</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Country</button>
        </div>

        <div class="mb-4">
            <input id="flt" type="text" placeholder="Filter countries…" class="input input-bordered input-sm w-full max-w-xs"
                oninput="var v=this.value.toLowerCase();document.querySelectorAll('#tbl tbody tr').forEach(function(r){{r.style.display=r.innerText.toLowerCase().indexOf(v)>-1?'':'none'}})"/>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table id="tbl" class="table">
                    <thead><tr><th>Name</th><th>Code</th><th>Alpha-3</th><th>Phone</th><th>Currency</th><th>Seq</th><th>Status</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4"><a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a></div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New Country</h3>
            <form method="post" action="/settings/countries">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" placeholder="e.g., Singapore" required/></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Code (ISO-2)</span></label>
                        <input type="text" name="code" class="input input-bordered" maxlength="3" placeholder="SG" required/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Alpha-3</span></label>
                        <input type="text" name="alpha3" class="input input-bordered" maxlength="3" placeholder="SGP"/></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Phone Code</span></label>
                        <input type="text" name="phone_code" class="input input-bordered" placeholder="+65"/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Currency</span></label>
                        <input type="text" name="currency_code" class="input input-bordered" maxlength="3" placeholder="SGD"/></div>
                </div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Sequence</span></label>
                    <input type="number" name="sequence" class="input input-bordered" value="100" min="0"/></div>
                <label class="cursor-pointer label justify-start gap-3 mb-2">
                    <input type="checkbox" name="active" class="checkbox checkbox-sm" checked/><span class="label-text">Active</span></label>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user = user.username, rows = rows_html
    );
    Html(html).into_response()
}

async fn country_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<CountryForm>,
) -> Response {
    let name = form.name.trim().to_string();
    let code = form.code.trim().to_uppercase();
    if name.is_empty() || code.is_empty() {
        return settings_write_error("/settings/countries", "Name and code are required.");
    }
    let alpha3 = form.alpha3.as_deref().map(|s| s.trim().to_uppercase()).filter(|s| !s.is_empty());
    let phone_code = form.phone_code.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let currency_code = form.currency_code.as_deref().map(|s| s.trim().to_uppercase()).filter(|s| !s.is_empty());

    let id = uuid::Uuid::now_v7();
    if let Err(e) = sqlx::query(
        "INSERT INTO countries (id, code, alpha3, name, phone_code, currency_code, sequence, active) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(id)
    .bind(&code)
    .bind(&alpha3)
    .bind(&name)
    .bind(phone_code)
    .bind(&currency_code)
    .bind(form.sequence.unwrap_or(100))
    .bind(form.active.is_some())
    .execute(&db)
    .await
    {
        error!(error = %e, "country create failed");
        return settings_write_error("/settings/countries", &format!("Could not create country: {e}"));
    }

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("country", id.to_string())
        .with_resource_name(&name)
        .with_details(serde_json::json!({"action": "create", "code": code}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/countries").into_response()
}

async fn country_edit(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let row = sqlx::query(
        "SELECT id, code, alpha3, name, phone_code, currency_code, sequence, active \
         FROM countries WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(c) = row else {
        return Redirect::to("/settings/countries").into_response();
    };

    let code: String = c.get("code");
    let alpha3: Option<String> = c.get("alpha3");
    let name: String = c.get("name");
    let phone_code: Option<String> = c.get("phone_code");
    let currency_code: Option<String> = c.get("currency_code");
    let sequence: i32 = c.get::<Option<i32>, _>("sequence").unwrap_or(100);
    let active: bool = c.get::<Option<bool>, _>("active").unwrap_or(true);

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{name} - Country</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{user}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-2xl">
        <div class="mb-6"><a href="/settings/countries" class="btn btn-ghost btn-sm">← Back to Countries</a></div>
        <div class="card bg-base-100 shadow"><div class="card-body">
            <h2 class="card-title">{name}</h2>
            <p class="text-base-content/60 mb-4">Edit country master data</p>
            <form method="post" action="/settings/countries/{id}">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" value="{name}" required/></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Code (ISO-2)</span></label>
                        <input type="text" name="code" class="input input-bordered" maxlength="3" value="{code}" required/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Alpha-3</span></label>
                        <input type="text" name="alpha3" class="input input-bordered" maxlength="3" value="{alpha3}"/></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Phone Code</span></label>
                        <input type="text" name="phone_code" class="input input-bordered" value="{phone}"/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Currency</span></label>
                        <input type="text" name="currency_code" class="input input-bordered" maxlength="3" value="{currency}"/></div>
                </div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Sequence</span></label>
                    <input type="number" name="sequence" class="input input-bordered" value="{sequence}" min="0"/></div>
                <label class="cursor-pointer label justify-start gap-3 mb-2">
                    <input type="checkbox" name="active" class="checkbox checkbox-sm" {active}/><span class="label-text">Active</span></label>
                <div class="card-actions justify-end mt-4"><button type="submit" class="btn btn-primary">Save Changes</button></div>
            </form>
        </div></div>
    </div>
</body>
</html>"##,
        user = user.username,
        id = id,
        name = html_escape(&name),
        code = html_escape(&code),
        alpha3 = html_escape(alpha3.as_deref().unwrap_or("")),
        phone = html_escape(phone_code.as_deref().unwrap_or("")),
        currency = html_escape(currency_code.as_deref().unwrap_or("")),
        sequence = sequence,
        active = if active { "checked" } else { "" },
    );
    Html(html).into_response()
}

async fn country_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<CountryForm>,
) -> Response {
    let name = form.name.trim().to_string();
    let code = form.code.trim().to_uppercase();
    if name.is_empty() || code.is_empty() {
        return settings_write_error(&format!("/settings/countries/{id}"), "Name and code are required.");
    }
    let alpha3 = form.alpha3.as_deref().map(|s| s.trim().to_uppercase()).filter(|s| !s.is_empty());
    let phone_code = form.phone_code.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let currency_code = form.currency_code.as_deref().map(|s| s.trim().to_uppercase()).filter(|s| !s.is_empty());

    if let Err(e) = sqlx::query(
        "UPDATE countries SET code = $1, alpha3 = $2, name = $3, phone_code = $4, \
         currency_code = $5, sequence = $6, active = $7, updated_at = NOW() WHERE id = $8"
    )
    .bind(&code)
    .bind(&alpha3)
    .bind(&name)
    .bind(phone_code)
    .bind(&currency_code)
    .bind(form.sequence.unwrap_or(100))
    .bind(form.active.is_some())
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "country update failed");
        return settings_write_error(&format!("/settings/countries/{id}"), &format!("Could not save country: {e}"));
    }

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("country", id.to_string())
        .with_resource_name(&name)
        .with_details(serde_json::json!({"action": "update", "code": code}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/countries").into_response()
}

// ── States ──────────────────────────────────────────────────────────────────

async fn states_list(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Optional country filter (?country_id=…).
    let filter_country: Option<uuid::Uuid> = query
        .get("country_id")
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());

    let states = if let Some(cid) = filter_country {
        sqlx::query(
            "SELECT s.id, s.code, s.name, s.active, c.name AS country_name \
             FROM states s JOIN countries c ON c.id = s.country_id \
             WHERE s.country_id = $1 ORDER BY c.name, s.name"
        )
        .bind(cid)
        .fetch_all(&db)
        .await
        .unwrap_or_default()
    } else {
        sqlx::query(
            "SELECT s.id, s.code, s.name, s.active, c.name AS country_name \
             FROM states s JOIN countries c ON c.id = s.country_id \
             ORDER BY c.name, s.name"
        )
        .fetch_all(&db)
        .await
        .unwrap_or_default()
    };

    let mut rows_html = String::new();
    for s in &states {
        let id: uuid::Uuid = s.get("id");
        let code: String = s.get("code");
        let name: String = s.get("name");
        let country_name: String = s.get("country_name");
        let active: bool = s.get::<Option<bool>, _>("active").unwrap_or(true);
        let status_badge = if active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else {
            r#"<span class="badge badge-warning badge-sm">Archived</span>"#
        };
        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/states/{}" class="link link-primary">{}</a></td>
                <td><code class="text-sm">{}</code></td>
                <td>{}</td>
                <td>{}</td>
            </tr>"##,
            id, html_escape(&name), html_escape(&code), html_escape(&country_name), status_badge
        ));
    }

    // Country dropdown (shared by the filter and the create modal).
    let countries = sqlx::query("SELECT id, name FROM countries WHERE active = true ORDER BY sequence, name")
        .fetch_all(&db)
        .await
        .unwrap_or_default();
    let mut filter_options = String::from(r#"<option value="">All countries</option>"#);
    let mut create_options = String::from(r#"<option value="">-- Select Country --</option>"#);
    for c in &countries {
        let cid: uuid::Uuid = c.get("id");
        let cname: String = c.get("name");
        let sel = if filter_country == Some(cid) { " selected" } else { "" };
        filter_options.push_str(&format!(r#"<option value="{}"{}>{}</option>"#, cid, sel, html_escape(&cname)));
        create_options.push_str(&format!(r#"<option value="{}">{}</option>"#, cid, html_escape(&cname)));
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>States - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{user}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">States / Provinces</h1>
                <p class="text-base-content/60">Maintain states per country</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New State</button>
        </div>

        <form method="get" action="/settings/states" class="mb-4 flex items-end gap-2">
            <div class="form-control">
                <label class="label"><span class="label-text">Filter by country</span></label>
                <select name="country_id" class="select select-bordered select-sm" onchange="this.form.submit()">{filter_options}</select>
            </div>
        </form>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table class="table">
                    <thead><tr><th>Name</th><th>Code</th><th>Country</th><th>Status</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4"><a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a></div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New State / Province</h3>
            <form method="post" action="/settings/states">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Country</span></label>
                    <select name="country_id" class="select select-bordered" required>{create_options}</select></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" placeholder="e.g., Selangor" required/></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Code</span></label>
                    <input type="text" name="code" class="input input-bordered" maxlength="10" placeholder="e.g., SGR" required/></div>
                <label class="cursor-pointer label justify-start gap-3 mb-2">
                    <input type="checkbox" name="active" class="checkbox checkbox-sm" checked/><span class="label-text">Active</span></label>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user = user.username, rows = rows_html, filter_options = filter_options, create_options = create_options
    );
    Html(html).into_response()
}

async fn state_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<StateForm>,
) -> Response {
    let name = form.name.trim().to_string();
    let code = form.code.trim().to_uppercase();
    if name.is_empty() || code.is_empty() {
        return settings_write_error("/settings/states", "Name and code are required.");
    }

    let id = uuid::Uuid::now_v7();
    if let Err(e) = sqlx::query(
        "INSERT INTO states (id, country_id, code, name, active) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(id)
    .bind(form.country_id)
    .bind(&code)
    .bind(&name)
    .bind(form.active.is_some())
    .execute(&db)
    .await
    {
        error!(error = %e, "state create failed");
        return settings_write_error("/settings/states", &format!("Could not create state: {e}"));
    }

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("state", id.to_string())
        .with_resource_name(&name)
        .with_details(serde_json::json!({"action": "create", "code": code, "country_id": form.country_id}));
    let _ = state.audit.log(entry).await;

    Redirect::to(&format!("/settings/states?country_id={}", form.country_id)).into_response()
}

async fn state_edit(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let row = sqlx::query(
        "SELECT id, country_id, code, name, active FROM states WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(s) = row else {
        return Redirect::to("/settings/states").into_response();
    };

    let country_id: uuid::Uuid = s.get("country_id");
    let code: String = s.get("code");
    let name: String = s.get("name");
    let active: bool = s.get::<Option<bool>, _>("active").unwrap_or(true);

    let countries = sqlx::query("SELECT id, name FROM countries ORDER BY sequence, name")
        .fetch_all(&db)
        .await
        .unwrap_or_default();
    let mut country_options = String::new();
    for c in &countries {
        let cid: uuid::Uuid = c.get("id");
        let cname: String = c.get("name");
        let sel = if cid == country_id { " selected" } else { "" };
        country_options.push_str(&format!(r#"<option value="{}"{}>{}</option>"#, cid, sel, html_escape(&cname)));
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{name} - State</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{user}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-2xl">
        <div class="mb-6"><a href="/settings/states" class="btn btn-ghost btn-sm">← Back to States</a></div>
        <div class="card bg-base-100 shadow"><div class="card-body">
            <h2 class="card-title">{name}</h2>
            <p class="text-base-content/60 mb-4">Edit state / province</p>
            <form method="post" action="/settings/states/{id}">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Country</span></label>
                    <select name="country_id" class="select select-bordered" required>{country_options}</select></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" value="{name}" required/></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Code</span></label>
                    <input type="text" name="code" class="input input-bordered" maxlength="10" value="{code}" required/></div>
                <label class="cursor-pointer label justify-start gap-3 mb-2">
                    <input type="checkbox" name="active" class="checkbox checkbox-sm" {active}/><span class="label-text">Active</span></label>
                <div class="card-actions justify-end mt-4"><button type="submit" class="btn btn-primary">Save Changes</button></div>
            </form>
        </div></div>
    </div>
</body>
</html>"##,
        user = user.username,
        id = id,
        name = html_escape(&name),
        code = html_escape(&code),
        country_options = country_options,
        active = if active { "checked" } else { "" },
    );
    Html(html).into_response()
}

async fn state_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<StateForm>,
) -> Response {
    let name = form.name.trim().to_string();
    let code = form.code.trim().to_uppercase();
    if name.is_empty() || code.is_empty() {
        return settings_write_error(&format!("/settings/states/{id}"), "Name and code are required.");
    }

    if let Err(e) = sqlx::query(
        "UPDATE states SET country_id = $1, code = $2, name = $3, active = $4, updated_at = NOW() WHERE id = $5"
    )
    .bind(form.country_id)
    .bind(&code)
    .bind(&name)
    .bind(form.active.is_some())
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "state update failed");
        return settings_write_error(&format!("/settings/states/{id}"), &format!("Could not save state: {e}"));
    }

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("state", id.to_string())
        .with_resource_name(&name)
        .with_details(serde_json::json!({"action": "update", "code": code, "country_id": form.country_id}));
    let _ = state.audit.log(entry).await;

    Redirect::to(&format!("/settings/states?country_id={}", form.country_id)).into_response()
}

// ============================================================================
// Stages — user-managed status-bar stages (record_stages)
//
// Data-driven backing for the core StatusBar widget: admins add / reorder /
// recolour / hide a model's stages here, no code change. A record stores the
// stage `code` in its own status column (e.g. contacts.record_state).
// ============================================================================

const STAGE_COLORS: [&str; 6] = ["neutral", "primary", "info", "success", "warning", "error"];

#[derive(Debug, serde::Deserialize)]
struct StageForm {
    model: String,
    code: String,
    label: String,
    color: Option<String>,
    sequence: Option<i32>,
    always_visible: Option<String>,
    locked: Option<String>,
    active: Option<String>,
}

fn stage_color_options(selected: &str) -> String {
    STAGE_COLORS
        .iter()
        .map(|c| {
            let sel = if *c == selected { " selected" } else { "" };
            let cap = c[..1].to_uppercase() + &c[1..];
            format!(r#"<option value="{c}"{sel}>{cap}</option>"#)
        })
        .collect()
}

async fn stages_list(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let stages = sqlx::query(
        "SELECT id, model, code, label, color, sequence, always_visible, active \
         FROM record_stages ORDER BY model, sequence, label",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Known model names for the datalist (model registry + existing stages).
    let models: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM ir_model UNION SELECT DISTINCT model FROM record_stages ORDER BY 1",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let datalist: String = models
        .iter()
        .map(|m| format!(r#"<option value="{}">"#, html_escape(m)))
        .collect();

    let mut rows_html = String::new();
    let mut current_model = String::new();
    for s in &stages {
        let id: uuid::Uuid = s.get("id");
        let model: String = s.get("model");
        let code: String = s.get("code");
        let label: String = s.get("label");
        let color: String = s.get("color");
        let sequence: i32 = s.get("sequence");
        let always: bool = s.get("always_visible");
        let locked: bool = s.get("locked");
        let active: bool = s.get("active");

        if model != current_model {
            rows_html.push_str(&format!(
                r#"<tr class="bg-base-200"><td colspan="7" class="font-semibold">{}</td></tr>"#,
                html_escape(&model)
            ));
            current_model = model.clone();
        }
        let vis = if always { "Always" } else { "When active" };
        let lock_badge = if locked {
            r#"<span class="badge badge-warning badge-sm gap-1">🔒 Locked</span>"#
        } else {
            r#"<span class="text-base-content/30">—</span>"#
        };
        let status = if active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else {
            r#"<span class="badge badge-warning badge-sm">Archived</span>"#
        };
        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/stages/{id}" class="link link-primary">{label}</a></td>
                <td><code class="text-xs">{code}</code></td>
                <td><span class="badge badge-{color}">{color}</span></td>
                <td>{seq}</td>
                <td>{vis}</td>
                <td>{lock}</td>
                <td>{status}</td>
            </tr>"##,
            id = id,
            label = html_escape(&label),
            code = html_escape(&code),
            color = html_escape(&color),
            seq = sequence,
            vis = vis,
            lock = lock_badge,
            status = status,
        ));
    }
    if stages.is_empty() {
        rows_html.push_str(r#"<tr><td colspan="7" class="text-center text-base-content/50 py-6">No stages yet — add one below.</td></tr>"#);
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stages - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{user}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Stages</h1>
                <p class="text-base-content/60">Status-bar stages per model — add, reorder, recolour, hide</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Stage</button>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table class="table">
                    <thead><tr><th>Label</th><th>Code</th><th>Color</th><th>Seq</th><th>Visibility</th><th>Lock</th><th>Status</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4"><a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a></div>
    </div>

    <datalist id="model-list">{datalist}</datalist>
    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New Stage</h3>
            <form method="post" action="/settings/stages">
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Model</span></label>
                        <input name="model" list="model-list" class="input input-bordered" placeholder="e.g. contacts" required/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Code</span></label>
                        <input name="code" class="input input-bordered" maxlength="50" placeholder="e.g. review" required/></div>
                </div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Label</span></label>
                    <input name="label" class="input input-bordered" placeholder="e.g. In Review" required/></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Color</span></label>
                        <select name="color" class="select select-bordered">{colors}</select></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Sequence</span></label>
                        <input name="sequence" type="number" class="input input-bordered" value="50" min="0"/></div>
                </div>
                <label class="cursor-pointer label justify-start gap-3 mb-2">
                    <input type="checkbox" name="always_visible" class="checkbox checkbox-sm" checked/>
                    <span class="label-text">Always visible (uncheck = show only when this stage is active)</span></label>
                <label class="cursor-pointer label justify-start gap-3 mb-2">
                    <input type="checkbox" name="locked" class="checkbox checkbox-sm"/>
                    <span class="label-text">Locked (records in this stage are read-only)</span></label>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user = user.username,
        rows = rows_html,
        datalist = datalist,
        colors = stage_color_options("neutral"),
    );
    Html(html).into_response()
}

async fn stage_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<StageForm>,
) -> Response {
    let model = form.model.trim().to_lowercase();
    let code = form.code.trim().to_lowercase();
    let label = form.label.trim().to_string();
    if model.is_empty() || code.is_empty() || label.is_empty() {
        return settings_write_error("/settings/stages", "Model, code and label are required.");
    }
    let color = form
        .color
        .as_deref()
        .filter(|c| STAGE_COLORS.contains(c))
        .unwrap_or("neutral");

    // Re-adding a previously-archived (model, code) reactivates it.
    if let Err(e) = sqlx::query(
        "INSERT INTO record_stages (model, code, label, color, sequence, always_visible, locked, active) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, true) \
         ON CONFLICT (model, code) DO UPDATE SET \
            label = EXCLUDED.label, color = EXCLUDED.color, sequence = EXCLUDED.sequence, \
            always_visible = EXCLUDED.always_visible, locked = EXCLUDED.locked, active = true, updated_at = NOW()",
    )
    .bind(&model)
    .bind(&code)
    .bind(&label)
    .bind(color)
    .bind(form.sequence.unwrap_or(50))
    .bind(form.always_visible.is_some())
    .bind(form.locked.is_some())
    .execute(&db)
    .await
    {
        error!(error = %e, "stage create failed");
        return settings_write_error("/settings/stages", &format!("Could not create stage: {e}"));
    }

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("record_stage", format!("{model}/{code}"))
        .with_resource_name(&label)
        .with_details(serde_json::json!({"action": "create", "model": model, "code": code}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/stages").into_response()
}

async fn stage_edit(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let row = sqlx::query(
        "SELECT id, model, code, label, color, sequence, always_visible, locked, active \
         FROM record_stages WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(s) = row else {
        return Redirect::to("/settings/stages").into_response();
    };
    let model: String = s.get("model");
    let code: String = s.get("code");
    let label: String = s.get("label");
    let color: String = s.get("color");
    let sequence: i32 = s.get("sequence");
    let always: bool = s.get("always_visible");
    let locked: bool = s.get("locked");
    let active: bool = s.get("active");

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{label} - Stage</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{user}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-2xl">
        <div class="mb-6"><a href="/settings/stages" class="btn btn-ghost btn-sm">← Back to Stages</a></div>
        <div class="card bg-base-100 shadow"><div class="card-body">
            <h2 class="card-title">{label} <span class="text-base-content/40 font-mono text-sm">{model}/{code}</span></h2>
            <p class="text-base-content/60 mb-4">Edit stage</p>
            <form method="post" action="/settings/stages/{id}">
                <input type="hidden" name="model" value="{model}"/>
                <input type="hidden" name="code" value="{code}"/>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Label</span></label>
                    <input name="label" class="input input-bordered" value="{label}" required/></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Color</span></label>
                        <select name="color" class="select select-bordered">{colors}</select></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Sequence</span></label>
                        <input name="sequence" type="number" class="input input-bordered" value="{seq}" min="0"/></div>
                </div>
                <label class="cursor-pointer label justify-start gap-3 mb-2">
                    <input type="checkbox" name="always_visible" class="checkbox checkbox-sm" {always}/>
                    <span class="label-text">Always visible</span></label>
                <label class="cursor-pointer label justify-start gap-3 mb-2">
                    <input type="checkbox" name="locked" class="checkbox checkbox-sm" {locked}/>
                    <span class="label-text">Locked (records in this stage are read-only)</span></label>
                <label class="cursor-pointer label justify-start gap-3 mb-2">
                    <input type="checkbox" name="active" class="checkbox checkbox-sm" {active}/>
                    <span class="label-text">Active</span></label>
                <div class="card-actions justify-between mt-4">
                    <form method="post" action="/settings/stages/{id}/delete" class="inline">
                        <button type="submit" class="btn btn-error btn-outline" onclick="return confirm('Archive this stage?');">Archive</button>
                    </form>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
            </form>
        </div></div>
    </div>
</body>
</html>"##,
        user = user.username,
        id = id,
        model = html_escape(&model),
        code = html_escape(&code),
        label = html_escape(&label),
        colors = stage_color_options(&color),
        seq = sequence,
        always = if always { "checked" } else { "" },
        locked = if locked { "checked" } else { "" },
        active = if active { "checked" } else { "" },
    );
    Html(html).into_response()
}

async fn stage_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<StageForm>,
) -> Response {
    let label = form.label.trim().to_string();
    if label.is_empty() {
        return settings_write_error(&format!("/settings/stages/{id}"), "Label is required.");
    }
    let color = form
        .color
        .as_deref()
        .filter(|c| STAGE_COLORS.contains(c))
        .unwrap_or("neutral");

    if let Err(e) = sqlx::query(
        "UPDATE record_stages SET label = $1, color = $2, sequence = $3, \
         always_visible = $4, locked = $5, active = $6, updated_at = NOW() WHERE id = $7",
    )
    .bind(&label)
    .bind(color)
    .bind(form.sequence.unwrap_or(50))
    .bind(form.always_visible.is_some())
    .bind(form.locked.is_some())
    .bind(form.active.is_some())
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "stage update failed");
        return settings_write_error(&format!("/settings/stages/{id}"), &format!("Could not save stage: {e}"));
    }

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("record_stage", id.to_string())
        .with_resource_name(&label)
        .with_details(serde_json::json!({"action": "update"}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/stages").into_response()
}

async fn stage_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Soft-archive so records still holding this code keep rendering it.
    let _ = sqlx::query("UPDATE record_stages SET active = false, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await;

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("record_stage", id.to_string())
        .with_details(serde_json::json!({"action": "archive"}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/stages").into_response()
}

// ============================================================================
// Stage Buttons — role-gated transition buttons (record_stage_actions)
// ============================================================================

const BUTTON_COLORS: [&str; 7] = ["primary", "success", "info", "warning", "error", "neutral", "ghost"];

#[derive(Debug, serde::Deserialize)]
struct StageButtonForm {
    model: String,
    label: String,
    target_stage: String,
    from_stage: Option<String>,
    required_role: Option<String>,
    color: Option<String>,
    sequence: Option<i32>,
    active: Option<String>,
}

fn button_color_options(selected: &str) -> String {
    BUTTON_COLORS
        .iter()
        .map(|c| {
            let sel = if *c == selected { " selected" } else { "" };
            let cap = c[..1].to_uppercase() + &c[1..];
            format!(r#"<option value="{c}"{sel}>{cap}</option>"#)
        })
        .collect()
}

async fn role_options(db: &sqlx::PgPool, selected: &str) -> String {
    let roles: Vec<String> = sqlx::query_scalar("SELECT name FROM roles ORDER BY name")
        .fetch_all(db)
        .await
        .unwrap_or_default();
    let mut out = format!(
        r#"<option value=""{}>— Anyone —</option>"#,
        if selected.is_empty() { " selected" } else { "" }
    );
    for r in &roles {
        let sel = if r == selected { " selected" } else { "" };
        out.push_str(&format!(r#"<option value="{r}"{sel}>{r}</option>"#, r = html_escape(r), sel = sel));
    }
    out
}

async fn stage_buttons_list(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let buttons = sqlx::query(
        "SELECT id, model, label, target_stage, from_stage, required_role, color, sequence, active \
         FROM record_stage_actions ORDER BY model, sequence, label",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let models: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM ir_model UNION SELECT DISTINCT model FROM record_stages ORDER BY 1",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let model_datalist: String = models.iter().map(|m| format!(r#"<option value="{}">"#, html_escape(m))).collect();
    let stage_codes: Vec<String> = sqlx::query_scalar("SELECT DISTINCT code FROM record_stages ORDER BY 1")
        .fetch_all(&db)
        .await
        .unwrap_or_default();
    let stage_datalist: String = stage_codes.iter().map(|c| format!(r#"<option value="{}">"#, html_escape(c))).collect();

    let mut rows_html = String::new();
    let mut current_model = String::new();
    for b in &buttons {
        let id: uuid::Uuid = b.get("id");
        let model: String = b.get("model");
        let label: String = b.get("label");
        let target: String = b.get("target_stage");
        let from: Option<String> = b.get("from_stage");
        let role: Option<String> = b.get("required_role");
        let color: String = b.get("color");
        let active: bool = b.get("active");

        if model != current_model {
            rows_html.push_str(&format!(
                r#"<tr class="bg-base-200"><td colspan="6" class="font-semibold">{}</td></tr>"#,
                html_escape(&model)
            ));
            current_model = model.clone();
        }
        let status = if active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else {
            r#"<span class="badge badge-warning badge-sm">Archived</span>"#
        };
        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/stage-buttons/{id}" class="link link-primary"><span class="badge badge-{color}">{label}</span></a></td>
                <td><code class="text-xs">{from}</code> → <code class="text-xs">{target}</code></td>
                <td>{role}</td>
                <td>{status}</td>
            </tr>"##,
            id = id,
            color = html_escape(&color),
            label = html_escape(&label),
            from = html_escape(from.as_deref().unwrap_or("any")),
            target = html_escape(&target),
            role = html_escape(role.as_deref().unwrap_or("Anyone")),
            status = status,
        ));
    }
    if buttons.is_empty() {
        rows_html.push_str(r#"<tr><td colspan="6" class="text-center text-base-content/50 py-6">No stage buttons yet — add one below.</td></tr>"#);
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stage Buttons - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{user}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Stage Buttons</h1>
                <p class="text-base-content/60">Role-gated buttons that move a record between stages</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Button</button>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table class="table">
                    <thead><tr><th>Button</th><th>Transition</th><th>Required role</th><th>Status</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4"><a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a></div>
    </div>

    <datalist id="model-list">{model_datalist}</datalist>
    <datalist id="stage-list">{stage_datalist}</datalist>
    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New Stage Button</h3>
            <form method="post" action="/settings/stage-buttons">
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Model</span></label>
                        <input name="model" list="model-list" class="input input-bordered" placeholder="contacts" required/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Button label</span></label>
                        <input name="label" class="input input-bordered" placeholder="Approve" required/></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">From stage (blank = any)</span></label>
                        <input name="from_stage" list="stage-list" class="input input-bordered" placeholder="confirmed"/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Moves to stage</span></label>
                        <input name="target_stage" list="stage-list" class="input input-bordered" placeholder="done" required/></div>
                </div>
                <div class="grid grid-cols-3 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Required role</span></label>
                        <select name="required_role" class="select select-bordered">{roles}</select></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Color</span></label>
                        <select name="color" class="select select-bordered">{colors}</select></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Sequence</span></label>
                        <input name="sequence" type="number" class="input input-bordered" value="10" min="0"/></div>
                </div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user = user.username,
        rows = rows_html,
        model_datalist = model_datalist,
        stage_datalist = stage_datalist,
        roles = role_options(&db, "").await,
        colors = button_color_options("primary"),
    );
    Html(html).into_response()
}

async fn stage_button_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<StageButtonForm>,
) -> Response {
    let model = form.model.trim().to_lowercase();
    let label = form.label.trim().to_string();
    let target = form.target_stage.trim().to_lowercase();
    if model.is_empty() || label.is_empty() || target.is_empty() {
        return settings_write_error("/settings/stage-buttons", "Model, label and target stage are required.");
    }
    let color = form.color.as_deref().filter(|c| BUTTON_COLORS.contains(c)).unwrap_or("primary");
    let from = form.from_stage.as_deref().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
    let role = form.required_role.as_deref().map(str::trim).filter(|s| !s.is_empty());

    if let Err(e) = sqlx::query(
        "INSERT INTO record_stage_actions (model, label, target_stage, from_stage, required_role, color, sequence, active) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, true) \
         ON CONFLICT (model, label) DO UPDATE SET \
            target_stage = EXCLUDED.target_stage, from_stage = EXCLUDED.from_stage, \
            required_role = EXCLUDED.required_role, color = EXCLUDED.color, \
            sequence = EXCLUDED.sequence, active = true, updated_at = NOW()",
    )
    .bind(&model)
    .bind(&label)
    .bind(&target)
    .bind(&from)
    .bind(role)
    .bind(color)
    .bind(form.sequence.unwrap_or(10))
    .execute(&db)
    .await
    {
        error!(error = %e, "stage button create failed");
        return settings_write_error("/settings/stage-buttons", &format!("Could not create button: {e}"));
    }

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("record_stage_action", format!("{model}/{label}"))
        .with_resource_name(&label)
        .with_details(serde_json::json!({"action": "create", "model": model, "target": target}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/stage-buttons").into_response()
}

async fn stage_button_edit(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let row = sqlx::query(
        "SELECT id, model, label, target_stage, from_stage, required_role, color, sequence, active \
         FROM record_stage_actions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(b) = row else {
        return Redirect::to("/settings/stage-buttons").into_response();
    };
    let model: String = b.get("model");
    let label: String = b.get("label");
    let target: String = b.get("target_stage");
    let from: String = b.get::<Option<String>, _>("from_stage").unwrap_or_default();
    let role: String = b.get::<Option<String>, _>("required_role").unwrap_or_default();
    let color: String = b.get("color");
    let sequence: i32 = b.get("sequence");
    let active: bool = b.get("active");

    let stage_codes: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT code FROM record_stages WHERE model = $1 ORDER BY 1",
    )
    .bind(&model)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let stage_datalist: String = stage_codes.iter().map(|c| format!(r#"<option value="{}">"#, html_escape(c))).collect();

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{label} - Stage Button</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{user}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-2xl">
        <div class="mb-6"><a href="/settings/stage-buttons" class="btn btn-ghost btn-sm">← Back to Stage Buttons</a></div>
        <div class="card bg-base-100 shadow"><div class="card-body">
            <h2 class="card-title">{label} <span class="text-base-content/40 font-mono text-sm">{model}</span></h2>
            <p class="text-base-content/60 mb-4">Edit transition button</p>
            <datalist id="stage-list">{stage_datalist}</datalist>
            <form method="post" action="/settings/stage-buttons/{id}">
                <input type="hidden" name="model" value="{model}"/>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Button label</span></label>
                    <input name="label" class="input input-bordered" value="{label}" required/></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">From stage (blank = any)</span></label>
                        <input name="from_stage" list="stage-list" class="input input-bordered" value="{from}"/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Moves to stage</span></label>
                        <input name="target_stage" list="stage-list" class="input input-bordered" value="{target}" required/></div>
                </div>
                <div class="grid grid-cols-3 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Required role</span></label>
                        <select name="required_role" class="select select-bordered">{roles}</select></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Color</span></label>
                        <select name="color" class="select select-bordered">{colors}</select></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Sequence</span></label>
                        <input name="sequence" type="number" class="input input-bordered" value="{seq}" min="0"/></div>
                </div>
                <label class="cursor-pointer label justify-start gap-3 mb-2">
                    <input type="checkbox" name="active" class="checkbox checkbox-sm" {active}/>
                    <span class="label-text">Active</span></label>
                <div class="card-actions justify-between mt-4">
                    <form method="post" action="/settings/stage-buttons/{id}/delete" class="inline">
                        <button type="submit" class="btn btn-error btn-outline" onclick="return confirm('Archive this button?');">Archive</button>
                    </form>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
            </form>
        </div></div>
    </div>
</body>
</html>"##,
        user = user.username,
        id = id,
        model = html_escape(&model),
        label = html_escape(&label),
        from = html_escape(&from),
        target = html_escape(&target),
        stage_datalist = stage_datalist,
        roles = role_options(&db, &role).await,
        colors = button_color_options(&color),
        seq = sequence,
        active = if active { "checked" } else { "" },
    );
    Html(html).into_response()
}

async fn stage_button_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<StageButtonForm>,
) -> Response {
    let label = form.label.trim().to_string();
    let target = form.target_stage.trim().to_lowercase();
    if label.is_empty() || target.is_empty() {
        return settings_write_error(&format!("/settings/stage-buttons/{id}"), "Label and target stage are required.");
    }
    let color = form.color.as_deref().filter(|c| BUTTON_COLORS.contains(c)).unwrap_or("primary");
    let from = form.from_stage.as_deref().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
    let role = form.required_role.as_deref().map(str::trim).filter(|s| !s.is_empty());

    if let Err(e) = sqlx::query(
        "UPDATE record_stage_actions SET label = $1, target_stage = $2, from_stage = $3, \
         required_role = $4, color = $5, sequence = $6, active = $7, updated_at = NOW() WHERE id = $8",
    )
    .bind(&label)
    .bind(&target)
    .bind(&from)
    .bind(role)
    .bind(color)
    .bind(form.sequence.unwrap_or(10))
    .bind(form.active.is_some())
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "stage button update failed");
        return settings_write_error(&format!("/settings/stage-buttons/{id}"), &format!("Could not save button: {e}"));
    }

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("record_stage_action", id.to_string())
        .with_resource_name(&label)
        .with_details(serde_json::json!({"action": "update"}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/stage-buttons").into_response()
}

async fn stage_button_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let _ = sqlx::query("UPDATE record_stage_actions SET active = false, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await;

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("record_stage_action", id.to_string())
        .with_details(serde_json::json!({"action": "archive"}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/stage-buttons").into_response()
}

// ============================================================================
// Approval Rules — multi-step sign-off attached to a stage button
// ============================================================================

#[derive(Debug, serde::Deserialize)]
struct ApprovalRuleForm {
    action_id: uuid::Uuid,
    step: Option<i32>,
    label: Option<String>,
    approver_role: String,
    min_approvals: Option<i32>,
}

/// GET /settings/approval-rules — admin view: every button, its ordered
/// approval steps, and a form to add a step. A button with ≥1 step requires
/// approval (handled generically by `vortex_framework::approval`).
async fn approval_rules_list(Db(db): Db, Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Approval Rules"))).into_response();
    }

    // Buttons that can carry approval rules (active transition buttons).
    let buttons = sqlx::query(
        "SELECT a.id, a.model, a.label, a.target_stage, \
                COUNT(r.id) AS steps \
         FROM record_stage_actions a \
         LEFT JOIN approval_rules r ON r.action_id = a.id \
         WHERE a.active = true \
         GROUP BY a.id, a.model, a.label, a.target_stage \
         ORDER BY a.model, a.label",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let rules = sqlx::query(
        "SELECT id, action_id, step, label, approver_role, min_approvals \
         FROM approval_rules ORDER BY action_id, step",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut button_opts = String::new();
    let mut cards = String::new();
    for b in &buttons {
        let aid: uuid::Uuid = b.get("id");
        let model: String = b.get("model");
        let label: String = b.get("label");
        let target: String = b.get("target_stage");
        let steps: i64 = b.get("steps");

        button_opts.push_str(&format!(
            r#"<option value="{aid}">{model} · {label} → {target}</option>"#,
            aid = aid,
            model = html_escape(&model),
            label = html_escape(&label),
            target = html_escape(&target),
        ));

        let mut step_rows = String::new();
        for r in rules.iter().filter(|r| r.get::<uuid::Uuid, _>("action_id") == aid) {
            let rid: uuid::Uuid = r.get("id");
            let step: i32 = r.get("step");
            let slabel: Option<String> = r.get("label");
            let role: String = r.get("approver_role");
            let minc: i32 = r.get("min_approvals");
            step_rows.push_str(&format!(
                r##"<tr>
                    <td class="font-mono">{step}</td>
                    <td>{slabel}</td>
                    <td><span class="badge badge-ghost">{role}</span></td>
                    <td>{minc}</td>
                    <td class="text-right"><form method="post" action="/settings/approval-rules/{rid}/delete" class="inline">
                        <button class="btn btn-xs btn-error btn-outline" onclick="return confirm('Remove this step?');">Remove</button>
                    </form></td>
                </tr>"##,
                step = step,
                slabel = html_escape(slabel.as_deref().unwrap_or("")),
                role = html_escape(&role),
                minc = minc,
                rid = rid,
            ));
        }
        let badge = if steps > 0 {
            format!(r#"<span class="badge badge-warning">{steps}-step approval</span>"#)
        } else {
            r#"<span class="badge badge-ghost">No approval</span>"#.to_string()
        };
        let table = if steps > 0 {
            format!(
                r#"<table class="table table-sm"><thead><tr><th>Step</th><th>Label</th><th>Approver role</th><th>Min</th><th></th></tr></thead><tbody>{step_rows}</tbody></table>"#
            )
        } else {
            r#"<p class="text-sm text-base-content/50">This button transitions immediately. Add a step below to require approval.</p>"#.to_string()
        };
        cards.push_str(&format!(
            r#"<div class="card bg-base-100 shadow mb-3"><div class="card-body p-4">
<div class="flex items-center justify-between"><h3 class="font-semibold">{model} · {label} <span class="text-base-content/40">→ {target}</span></h3>{badge}</div>
{table}
</div></div>"#,
            model = html_escape(&model),
            label = html_escape(&label),
            target = html_escape(&target),
            badge = badge,
            table = table,
        ));
    }
    if buttons.is_empty() {
        cards.push_str(r#"<div class="alert">No stage buttons yet. Create one under Settings ▸ Stage Buttons first, then add approval steps here.</div>"#);
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Approval Rules - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{user}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-3xl">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Approval Rules</h1>
                <p class="text-base-content/60">Require sequential sign-off before a stage button takes effect. Each step names an approver role and how many approvals it needs; steps run in order.</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ Add Step</button>
        </div>

        {cards}

        <div class="mt-4"><a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a></div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">Add Approval Step</h3>
            <form method="post" action="/settings/approval-rules">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Button</span></label>
                    <select name="action_id" class="select select-bordered" required>{button_opts}</select></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Step order</span></label>
                        <input name="step" type="number" class="input input-bordered" value="1" min="1" required/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Min approvals</span></label>
                        <input name="min_approvals" type="number" class="input input-bordered" value="1" min="1" required/></div>
                </div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Step label</span></label>
                    <input name="label" class="input input-bordered" placeholder="Manager review"/></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Approver role</span></label>
                    <select name="approver_role" class="select select-bordered" required>{roles}</select></div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add Step</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user = html_escape(&user.username),
        cards = cards,
        button_opts = button_opts,
        roles = role_options(&db, "").await,
    );
    Html(html).into_response()
}

/// POST /settings/approval-rules — add one step to a button.
async fn approval_rule_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<ApprovalRuleForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Approval Rules"))).into_response();
    }
    let role = form.approver_role.trim().to_string();
    if role.is_empty() {
        return settings_write_error("/settings/approval-rules", "An approver role is required.");
    }
    let step = form.step.unwrap_or(1).max(1);
    let minc = form.min_approvals.unwrap_or(1).max(1);
    let label = form.label.as_deref().map(str::trim).filter(|s| !s.is_empty());

    if let Err(e) = sqlx::query(
        "INSERT INTO approval_rules (action_id, step, label, approver_role, min_approvals) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (action_id, step) DO UPDATE SET \
            label = EXCLUDED.label, approver_role = EXCLUDED.approver_role, \
            min_approvals = EXCLUDED.min_approvals",
    )
    .bind(form.action_id)
    .bind(step)
    .bind(label)
    .bind(&role)
    .bind(minc)
    .execute(&db)
    .await
    {
        error!(error = %e, "approval rule create failed");
        return settings_write_error("/settings/approval-rules", &format!("Could not add step: {e}"));
    }

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("approval_rule", form.action_id.to_string())
        .with_details(serde_json::json!({"action": "create", "step": step, "role": role}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/approval-rules").into_response()
}

/// POST /settings/approval-rules/:id/delete — drop one step.
async fn approval_rule_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Approval Rules"))).into_response();
    }
    let _ = sqlx::query("DELETE FROM approval_rules WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await;

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("approval_rule", id.to_string())
        .with_details(serde_json::json!({"action": "delete"}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/approval-rules").into_response()
}

// ============================================================================
// Approvals — generic, cross-module inbox + decisions
// ============================================================================

#[derive(Debug, serde::Deserialize)]
struct DecisionForm {
    comment: Option<String>,
}

/// GET /approvals — the signed-in user's approval inbox: every pending request
/// they may act on right now, across all modules. Generic over the model.
async fn approvals_inbox(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    use vortex_framework::approval;
    let pending = approval::inbox(&db, user.id, &user.roles).await;

    let mut rows = String::new();
    for r in &pending {
        // Convention: a record's detail page lives at /{model}/{record_id}.
        let link = format!("/{}/{}", r.model, r.record_id);
        rows.push_str(&format!(
            r##"<tr>
                <td><a href="{link}" class="link link-primary">{name}</a><div class="text-xs text-base-content/50">{model}</div></td>
                <td><code class="text-xs">{from}</code> → <code class="text-xs">{target}</code></td>
                <td>{req_by}</td>
                <td>step {step}</td>
                <td class="text-right">
                    <form method="post" action="/approvals/{id}/approve" class="inline"><button class="btn btn-xs btn-success">Approve</button></form>
                    <form method="post" action="/approvals/{id}/reject" class="inline"><button class="btn btn-xs btn-error btn-outline" onclick="return confirm('Reject this request?');">Reject</button></form>
                </td>
            </tr>"##,
            link = html_escape(&link),
            name = html_escape(r.resource_name.as_deref().unwrap_or("(record)")),
            model = html_escape(&r.model),
            from = html_escape(r.from_stage.as_deref().unwrap_or("")),
            target = html_escape(&r.target_stage),
            req_by = html_escape(r.requested_by_name.as_deref().unwrap_or("")),
            step = r.current_step,
            id = r.id,
        ));
    }
    if pending.is_empty() {
        rows.push_str(r#"<tr><td colspan="5" class="text-center text-base-content/50 py-8">Nothing awaiting your approval.</td></tr>"#);
    }

    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("approvals", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    let content = format!(
        r##"<div class="mb-6"><h1 class="text-2xl font-bold">Approvals</h1>
<p class="text-base-content/60 text-sm">Requests awaiting your sign-off · {count} pending</p></div>
<div class="card bg-base-100 shadow"><div class="card-body p-0 overflow-x-auto">
<table class="table">
<thead><tr><th>Record</th><th>Transition</th><th>Requested by</th><th>Stage</th><th></th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div></div>"##,
        count = pending.len(),
        rows = rows,
    );

    let html = format!(
        r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><title>Approvals - Remicle</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">{content}</main></div></body></html>"#,
        sidebar = sidebar,
        content = content,
    );
    Html(html).into_response()
}

/// Redirect a decision back to where it was made (the record page if the
/// form was posted from there, else the inbox).
fn decision_redirect(headers: &HeaderMap) -> Redirect {
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .filter(|r| !r.contains("/approvals"))
        .map(|s| s.to_string());
    match referer {
        Some(url) => Redirect::to(&url),
        None => Redirect::to("/approvals"),
    }
}

/// POST /approvals/:id/approve
async fn approval_approve(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Form(form): Form<DecisionForm>,
) -> Response {
    use vortex_framework::approval;
    let outcome = approval::decide(
        &db, &state.audit, &db_ctx.db_name, id,
        user.id, &user.username, &user.roles,
        true, form.comment.as_deref().unwrap_or(""),
    )
    .await;
    info!(?outcome, request = %id, "approval decision");
    decision_redirect(&headers).into_response()
}

/// POST /approvals/:id/reject
async fn approval_reject(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Form(form): Form<DecisionForm>,
) -> Response {
    use vortex_framework::approval;
    let outcome = approval::decide(
        &db, &state.audit, &db_ctx.db_name, id,
        user.id, &user.username, &user.roles,
        false, form.comment.as_deref().unwrap_or(""),
    )
    .await;
    info!(?outcome, request = %id, "approval decision");
    decision_redirect(&headers).into_response()
}

// ============================================================================
// Email / SMTP servers — per-tenant outbound mail (vortex_framework::mail)
// ============================================================================

#[derive(Debug, serde::Deserialize)]
struct MailServerForm {
    name: String,
    provider: Option<String>,
    host: String,
    port: Option<i32>,
    security: Option<String>,
    username: Option<String>,
    password: Option<String>,
    from_address: String,
    from_name: Option<String>,
    is_default: Option<String>,
    active: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct MailTestForm {
    to: String,
}

fn provider_options(selected: &str) -> String {
    vortex_framework::mail::PROVIDERS
        .iter()
        .map(|(val, label)| {
            let sel = if *val == selected { " selected" } else { "" };
            format!(r#"<option value="{val}"{sel}>{label}</option>"#, val = val, label = label, sel = sel)
        })
        .collect()
}

fn security_options(selected: &str) -> String {
    [("starttls", "STARTTLS (587)"), ("tls", "TLS / SSL (465)"), ("none", "None (25)")]
        .iter()
        .map(|(val, label)| {
            let sel = if *val == selected { " selected" } else { "" };
            format!(r#"<option value="{val}"{sel}>{label}</option>"#, val = val, label = label, sel = sel)
        })
        .collect()
}

async fn email_servers_list(Db(db): Db, Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Email Settings"))).into_response();
    }
    let servers = sqlx::query(
        "SELECT id, name, provider, host, port, security, from_address, is_default, active, \
                (username IS NOT NULL) AS has_auth \
         FROM mail_servers ORDER BY is_default DESC, name",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows = String::new();
    for s in &servers {
        let id: uuid::Uuid = s.get("id");
        let name: String = s.get("name");
        let provider: String = s.get("provider");
        let host: String = s.get("host");
        let port: i32 = s.get("port");
        let security: String = s.get("security");
        let from_address: String = s.get("from_address");
        let is_default: bool = s.get("is_default");
        let active: bool = s.get("active");
        let default_badge = if is_default { r#" <span class="badge badge-primary badge-sm">default</span>"# } else { "" };
        let status = if active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else {
            r#"<span class="badge badge-ghost badge-sm">Disabled</span>"#
        };
        rows.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/email/{id}" class="link link-primary font-medium">{name}</a>{default_badge}<div class="text-xs text-base-content/50">{provider}</div></td>
                <td><code class="text-xs">{host}:{port}</code> · {security}</td>
                <td>{from_address}</td>
                <td>{status}</td>
                <td>
                    <form method="post" action="/settings/email/{id}/test" class="flex gap-1 items-center">
                        <input name="to" type="email" class="input input-bordered input-xs w-44" placeholder="test@example.com" required/>
                        <button class="btn btn-xs btn-outline">Send test</button>
                    </form>
                </td>
            </tr>"##,
            id = id,
            name = html_escape(&name),
            default_badge = default_badge,
            provider = html_escape(&provider),
            host = html_escape(&host),
            port = port,
            security = html_escape(&security),
            from_address = html_escape(&from_address),
            status = status,
        ));
    }
    if servers.is_empty() {
        rows.push_str(r#"<tr><td colspan="5" class="text-center text-base-content/50 py-8">No mail servers yet — add one to enable outbound email.</td></tr>"#);
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email / SMTP - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{user}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-4xl">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Email / SMTP</h1>
                <p class="text-base-content/60">Outbound mail servers for this tenant. Passwords are encrypted at rest. The default server is used by the system and by modules that send mail.</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Server</button>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0 overflow-x-auto">
                <table class="table">
                    <thead><tr><th>Name</th><th>Host</th><th>From</th><th>Status</th><th>Test</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4"><a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a></div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box max-w-xl">
            <h3 class="font-bold text-lg mb-4">New Mail Server</h3>
            <form method="post" action="/settings/email">
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Name</span></label>
                        <input name="name" class="input input-bordered" placeholder="Company mailbox" required/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Provider</span></label>
                        <select name="provider" id="provider-sel" class="select select-bordered" onchange="applyPreset()">{providers}</select></div>
                </div>
                <div class="grid grid-cols-3 gap-4">
                    <div class="form-control mb-3 col-span-2"><label class="label"><span class="label-text">SMTP host</span></label>
                        <input name="host" id="host-inp" class="input input-bordered" placeholder="smtp.example.com" required/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Port</span></label>
                        <input name="port" id="port-inp" type="number" class="input input-bordered" value="587"/></div>
                </div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Security</span></label>
                    <select name="security" id="sec-sel" class="select select-bordered">{security}</select></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Username</span></label>
                        <input name="username" class="input input-bordered" placeholder="apikey or user@domain" autocomplete="off"/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Password / app password</span></label>
                        <input name="password" type="password" class="input input-bordered" autocomplete="new-password"/></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">From address</span></label>
                        <input name="from_address" type="email" class="input input-bordered" placeholder="noreply@domain" required/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">From name</span></label>
                        <input name="from_name" class="input input-bordered" placeholder="Acme ERP"/></div>
                </div>
                <label class="cursor-pointer label justify-start gap-3 mb-2">
                    <input type="checkbox" name="is_default" class="checkbox checkbox-sm" checked/>
                    <span class="label-text">Use as default server</span></label>
                <p class="text-xs text-base-content/50 mb-2">Gmail and Microsoft 365 require an <strong>app password</strong> (not your login password) when 2FA is on.</p>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
    <script>
    function applyPreset() {{
        var presets = {{
            gmail:      {{host:'smtp.gmail.com', port:587, sec:'starttls'}},
            office365:  {{host:'smtp.office365.com', port:587, sec:'starttls'}},
            sendgrid:   {{host:'smtp.sendgrid.net', port:587, sec:'starttls'}},
            mailgun:    {{host:'smtp.mailgun.org', port:587, sec:'starttls'}}
        }};
        var p = presets[document.getElementById('provider-sel').value];
        if (p) {{
            document.getElementById('host-inp').value = p.host;
            document.getElementById('port-inp').value = p.port;
            document.getElementById('sec-sel').value = p.sec;
        }}
    }}
    </script>
</body>
</html>"##,
        user = html_escape(&user.username),
        rows = rows,
        providers = provider_options("generic"),
        security = security_options("starttls"),
    );
    Html(html).into_response()
}

/// Clear the default flag on all other servers (the partial unique index
/// allows only one). Call before setting a new default.
async fn clear_other_defaults(db: &sqlx::PgPool, keep: Option<uuid::Uuid>) {
    let _ = match keep {
        Some(id) => sqlx::query("UPDATE mail_servers SET is_default = false WHERE is_default AND id <> $1").bind(id).execute(db).await,
        None => sqlx::query("UPDATE mail_servers SET is_default = false WHERE is_default").execute(db).await,
    };
}

async fn email_server_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<MailServerForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Email Settings"))).into_response();
    }
    let name = form.name.trim().to_string();
    let host = form.host.trim().to_string();
    let from_address = form.from_address.trim().to_string();
    if name.is_empty() || host.is_empty() || from_address.is_empty() {
        return settings_write_error("/settings/email", "Name, host and from-address are required.");
    }
    let provider = form.provider.as_deref().unwrap_or("generic").to_string();
    let security = form.security.as_deref().unwrap_or("starttls").to_string();
    let port = form.port.unwrap_or(587);
    let username = form.username.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let from_name = form.from_name.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let is_default = form.is_default.is_some();

    // Encrypt the password (if any) before it ever touches the row.
    let password_enc: Option<Vec<u8>> = match form.password.as_deref().filter(|p| !p.is_empty()) {
        Some(p) => match vortex_security::crypto::encrypt_str(p, &vortex_security::crypto::master_key()) {
            Ok(blob) => Some(blob),
            Err(_) => return settings_write_error("/settings/email", "Could not encrypt the password."),
        },
        None => None,
    };

    if is_default {
        clear_other_defaults(&db, None).await;
    }
    if let Err(e) = sqlx::query(
        "INSERT INTO mail_servers (name, provider, host, port, security, username, password_enc, from_address, from_name, is_default) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(&name).bind(&provider).bind(&host).bind(port).bind(&security)
    .bind(username).bind(password_enc.as_deref()).bind(&from_address).bind(from_name).bind(is_default)
    .execute(&db)
    .await
    {
        error!(error = %e, "mail server create failed");
        return settings_write_error("/settings/email", &format!("Could not save server: {e}"));
    }

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("mail_server", &name)
        .with_resource_name(&name)
        .with_details(serde_json::json!({"action": "create", "host": host, "provider": provider}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/email").into_response()
}

async fn email_server_edit(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Email Settings"))).into_response();
    }
    let row = sqlx::query(
        "SELECT id, name, provider, host, port, security, username, from_address, from_name, is_default, active, \
                (password_enc IS NOT NULL) AS has_pw \
         FROM mail_servers WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(s) = row else { return Redirect::to("/settings/email").into_response(); };
    let name: String = s.get("name");
    let provider: String = s.get("provider");
    let host: String = s.get("host");
    let port: i32 = s.get("port");
    let security: String = s.get("security");
    let username: String = s.get::<Option<String>, _>("username").unwrap_or_default();
    let from_address: String = s.get("from_address");
    let from_name: String = s.get::<Option<String>, _>("from_name").unwrap_or_default();
    let is_default: bool = s.get("is_default");
    let active: bool = s.get("active");
    let has_pw: bool = s.get("has_pw");
    let pw_placeholder = if has_pw { "•••••••• (unchanged)" } else { "" };

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{name} - Mail Server</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{user}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-xl">
        <div class="mb-6"><a href="/settings/email" class="btn btn-ghost btn-sm">← Back to Email Settings</a></div>
        <div class="card bg-base-100 shadow"><div class="card-body">
            <h2 class="card-title">{name}</h2>
            <form method="post" action="/settings/email/{id}">
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Name</span></label>
                        <input name="name" class="input input-bordered" value="{name}" required/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Provider</span></label>
                        <select name="provider" class="select select-bordered">{providers}</select></div>
                </div>
                <div class="grid grid-cols-3 gap-4">
                    <div class="form-control mb-3 col-span-2"><label class="label"><span class="label-text">SMTP host</span></label>
                        <input name="host" class="input input-bordered" value="{host}" required/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Port</span></label>
                        <input name="port" type="number" class="input input-bordered" value="{port}"/></div>
                </div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Security</span></label>
                    <select name="security" class="select select-bordered">{security}</select></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Username</span></label>
                        <input name="username" class="input input-bordered" value="{username}" autocomplete="off"/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">Password (blank = keep)</span></label>
                        <input name="password" type="password" class="input input-bordered" placeholder="{pw_placeholder}" autocomplete="new-password"/></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3"><label class="label"><span class="label-text">From address</span></label>
                        <input name="from_address" type="email" class="input input-bordered" value="{from_address}" required/></div>
                    <div class="form-control mb-3"><label class="label"><span class="label-text">From name</span></label>
                        <input name="from_name" class="input input-bordered" value="{from_name}"/></div>
                </div>
                <div class="flex gap-6">
                    <label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="is_default" class="checkbox checkbox-sm" {default_checked}/><span class="label-text">Default server</span></label>
                    <label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="active" class="checkbox checkbox-sm" {active_checked}/><span class="label-text">Active</span></label>
                </div>
                <div class="card-actions justify-between mt-4">
                    <form method="post" action="/settings/email/{id}/delete" class="inline">
                        <button type="submit" class="btn btn-error btn-outline" onclick="return confirm('Delete this server?');">Delete</button>
                    </form>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
            </form>
            <div class="divider">Test</div>
            <form method="post" action="/settings/email/{id}/test" class="flex gap-2 items-end">
                <div class="form-control flex-1"><label class="label"><span class="label-text">Send a test email to</span></label>
                    <input name="to" type="email" class="input input-bordered" placeholder="you@example.com" required/></div>
                <button class="btn btn-outline">Send test</button>
            </form>
        </div></div>
    </div>
</body>
</html>"##,
        user = html_escape(&user.username),
        id = id,
        name = html_escape(&name),
        providers = provider_options(&provider),
        host = html_escape(&host),
        port = port,
        security = security_options(&security),
        username = html_escape(&username),
        pw_placeholder = pw_placeholder,
        from_address = html_escape(&from_address),
        from_name = html_escape(&from_name),
        default_checked = if is_default { "checked" } else { "" },
        active_checked = if active { "checked" } else { "" },
    );
    Html(html).into_response()
}

async fn email_server_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<MailServerForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Email Settings"))).into_response();
    }
    let name = form.name.trim().to_string();
    let host = form.host.trim().to_string();
    let from_address = form.from_address.trim().to_string();
    if name.is_empty() || host.is_empty() || from_address.is_empty() {
        return settings_write_error(&format!("/settings/email/{id}"), "Name, host and from-address are required.");
    }
    let provider = form.provider.as_deref().unwrap_or("generic").to_string();
    let security = form.security.as_deref().unwrap_or("starttls").to_string();
    let port = form.port.unwrap_or(587);
    let username = form.username.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let from_name = form.from_name.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let is_default = form.is_default.is_some();
    let active = form.active.is_some();

    if is_default {
        clear_other_defaults(&db, Some(id)).await;
    }

    // Update everything except the password first.
    if let Err(e) = sqlx::query(
        "UPDATE mail_servers SET name=$1, provider=$2, host=$3, port=$4, security=$5, \
         username=$6, from_address=$7, from_name=$8, is_default=$9, active=$10, updated_at=NOW() WHERE id=$11",
    )
    .bind(&name).bind(&provider).bind(&host).bind(port).bind(&security)
    .bind(username).bind(&from_address).bind(from_name).bind(is_default).bind(active).bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "mail server update failed");
        return settings_write_error(&format!("/settings/email/{id}"), &format!("Could not save server: {e}"));
    }

    // Only overwrite the password when a new one is supplied.
    if let Some(p) = form.password.as_deref().filter(|p| !p.is_empty()) {
        match vortex_security::crypto::encrypt_str(p, &vortex_security::crypto::master_key()) {
            Ok(blob) => {
                let _ = sqlx::query("UPDATE mail_servers SET password_enc=$1, updated_at=NOW() WHERE id=$2")
                    .bind(blob).bind(id).execute(&db).await;
            }
            Err(_) => return settings_write_error(&format!("/settings/email/{id}"), "Could not encrypt the password."),
        }
    }

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("mail_server", id.to_string())
        .with_resource_name(&name)
        .with_details(serde_json::json!({"action": "update"}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/email").into_response()
}

async fn email_server_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Email Settings"))).into_response();
    }
    let _ = sqlx::query("DELETE FROM mail_servers WHERE id = $1").bind(id).execute(&db).await;

    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("mail_server", id.to_string())
        .with_details(serde_json::json!({"action": "delete"}));
    let _ = state.audit.log(entry).await;

    Redirect::to("/settings/email").into_response()
}

async fn email_server_test(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<MailTestForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Email Settings"))).into_response();
    }
    let to = form.to.trim().to_string();
    let Some(server) = vortex_framework::mail::server_by_id(&db, id).await else {
        return settings_write_error("/settings/email", "Server not found.");
    };
    let msg = vortex_framework::mail::EmailMessage::text(
        &to,
        "Vortex SMTP test",
        format!(
            "This is a test message from Vortex via '{}' ({}:{}).\n\nIf you received it, outbound email is working.",
            server.name, server.host, server.port
        ),
    );
    match vortex_framework::mail::send_with(&db, &server, &msg, "test").await {
        Ok(()) => settings_write_ok("/settings/email", &format!("Test email sent to {to}.")),
        Err(e) => settings_write_error("/settings/email", &format!("Send failed: {e}")),
    }
}

// ============================================================================
// Background jobs — durable queue admin (ir_job, central in the primary DB)
// ============================================================================

async fn jobs_list(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Jobs"))).into_response();
    }
    // The queue is central: query the primary pool, not the request tenant.
    let filter = q.get("status").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let rows = if let Some(f) = filter {
        sqlx::query("SELECT id, kind, status, attempts, max_attempts, run_at, last_error, db_name, created_at FROM ir_job WHERE status=$1 ORDER BY created_at DESC LIMIT 200")
            .bind(f).fetch_all(&state.db).await
    } else {
        sqlx::query("SELECT id, kind, status, attempts, max_attempts, run_at, last_error, db_name, created_at FROM ir_job ORDER BY created_at DESC LIMIT 200")
            .fetch_all(&state.db).await
    }.unwrap_or_default();

    // Status counts for the summary chips.
    let counts = sqlx::query("SELECT status, COUNT(*) AS n FROM ir_job GROUP BY status")
        .fetch_all(&state.db).await.unwrap_or_default();
    let mut chips = String::new();
    for c in &counts {
        let s: String = c.get("status");
        let n: i64 = c.get("n");
        chips.push_str(&format!(r#"<a href="/settings/jobs?status={s}" class="badge badge-outline gap-1">{s}: {n}</a> "#, s = html_escape(&s), n = n));
    }

    let mut body = String::new();
    for r in &rows {
        let id: uuid::Uuid = r.get("id");
        let kind: String = r.get("kind");
        let status: String = r.get("status");
        let attempts: i32 = r.get("attempts");
        let max_attempts: i32 = r.get("max_attempts");
        let run_at: chrono::DateTime<chrono::Utc> = r.get("run_at");
        let last_error: Option<String> = r.try_get("last_error").ok().flatten();
        let db_name: Option<String> = r.try_get("db_name").ok().flatten();
        let badge = match status.as_str() {
            "succeeded" => "badge-success", "dead" => "badge-error",
            "running" => "badge-info", "cancelled" => "badge-ghost", _ => "badge-warning",
        };
        let actions = if status == "dead" || status == "cancelled" {
            format!(r#"<form method="post" action="/settings/jobs/{id}/retry" class="inline"><button class="btn btn-xs btn-outline">Retry</button></form>"#)
        } else if status == "pending" {
            format!(r#"<form method="post" action="/settings/jobs/{id}/cancel" class="inline"><button class="btn btn-xs btn-error btn-outline">Cancel</button></form>"#)
        } else { String::new() };
        body.push_str(&format!(
            r##"<tr><td><code class="text-xs">{kind}</code><div class="text-xs opacity-40">{db}</div></td>
            <td><span class="badge {badge} badge-sm">{status}</span></td>
            <td class="text-xs">{attempts}/{max}</td>
            <td class="text-xs">{run_at}</td>
            <td class="text-xs text-error">{err}</td>
            <td class="text-right">{actions}</td></tr>"##,
            kind = html_escape(&kind), db = html_escape(db_name.as_deref().unwrap_or("")),
            badge = badge, status = html_escape(&status), attempts = attempts, max = max_attempts,
            run_at = run_at.format("%Y-%m-%d %H:%M"),
            err = html_escape(last_error.as_deref().unwrap_or("")), actions = actions,
        ));
    }
    if rows.is_empty() {
        body.push_str(r#"<tr><td colspan="6" class="text-center opacity-50 py-8">No jobs.</td></tr>"#);
    }

    let html = format!(
        r##"<!DOCTYPE html><html lang="en" data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Jobs - Settings</title>
<link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="navbar bg-base-100 shadow-lg"><div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div><div class="flex-none"><span class="text-sm">@{user}</span></div></div>
<div class="container mx-auto p-6 max-w-5xl">
<div class="mb-4"><h1 class="text-2xl font-bold">Background Jobs</h1>
<p class="text-base-content/60">Durable queue — retries with backoff, dead-letters after max attempts. Central across tenants.</p></div>
<div class="mb-3 flex flex-wrap gap-1 items-center"><a href="/settings/jobs" class="badge badge-primary">all</a> {chips}</div>
<div class="card bg-base-100 shadow"><div class="card-body p-0 overflow-x-auto">
<table class="table table-sm"><thead><tr><th>Kind</th><th>Status</th><th>Tries</th><th>Run at (UTC)</th><th>Last error</th><th></th></tr></thead><tbody>{body}</tbody></table>
</div></div>
<div class="mt-4"><a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a></div>
</div></body></html>"##,
        user = html_escape(&user.username), chips = chips, body = body,
    );
    Html(html).into_response()
}

async fn job_retry(State(state): State<Arc<AppState>>, Extension(user): Extension<AuthUser>, Path(id): Path<uuid::Uuid>) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Jobs"))).into_response();
    }
    let _ = sqlx::query("UPDATE ir_job SET status='pending', attempts=0, run_at=NOW(), locked_at=NULL, locked_by=NULL, last_error=NULL, finished_at=NULL, updated_at=NOW() WHERE id=$1")
        .bind(id).execute(&state.db).await;
    Redirect::to("/settings/jobs").into_response()
}

async fn job_cancel(State(state): State<Arc<AppState>>, Extension(user): Extension<AuthUser>, Path(id): Path<uuid::Uuid>) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Jobs"))).into_response();
    }
    let _ = sqlx::query("UPDATE ir_job SET status='cancelled', finished_at=NOW(), updated_at=NOW() WHERE id=$1 AND status IN ('pending','dead')")
        .bind(id).execute(&state.db).await;
    Redirect::to("/settings/jobs").into_response()
}

// ============================================================================
// API Tokens Management (bearer credentials for the public REST API)
// ============================================================================

fn api_tokens_page_shell(user: &AuthUser, inner: &str) -> Html<String> {
    Html(format!(
        r##"<!DOCTYPE html><html lang="en" data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>API Tokens - Settings</title>
<link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="navbar bg-base-100 shadow-lg"><div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div><div class="flex-none"><span class="text-sm">@{user}</span></div></div>
<div class="container mx-auto p-6 max-w-5xl">{inner}</div></body></html>"##,
        user = html_escape(&user.username),
        inner = inner,
    ))
}

async fn api_tokens_list(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("API Tokens"))).into_response();
    }
    let tokens = vortex_framework::api::list_tokens(&db).await;

    // Owner select options (active users).
    let users = sqlx::query("SELECT id, username FROM users WHERE active = true ORDER BY username")
        .fetch_all(&db).await.unwrap_or_default();
    let mut options = String::new();
    for u in &users {
        let id: uuid::Uuid = u.get("id");
        let uname: String = u.get("username");
        options.push_str(&format!(r#"<option value="{id}">{uname}</option>"#, id = id, uname = html_escape(&uname)));
    }

    let mut rows = String::new();
    for t in &tokens {
        let status = if t.revoked {
            r#"<span class="badge badge-ghost badge-sm">revoked</span>"#.to_string()
        } else if t.expires_at.map(|e| e < chrono::Utc::now()).unwrap_or(false) {
            r#"<span class="badge badge-warning badge-sm">expired</span>"#.to_string()
        } else {
            r#"<span class="badge badge-success badge-sm">active</span>"#.to_string()
        };
        let scopes = if t.scopes.is_empty() { "read".to_string() } else { format!("read, {}", t.scopes.join(", ")) };
        let last = t.last_used_at.map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "—".into());
        let exp = t.expires_at.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_else(|| "never".into());
        let revoke = if t.revoked {
            String::new()
        } else {
            format!(r#"<form method="post" action="/settings/api-tokens/{id}/revoke" class="inline" onsubmit="return confirm('Revoke this token? Clients using it will stop working immediately.')"><button class="btn btn-xs btn-error btn-outline">Revoke</button></form>"#, id = t.id)
        };
        rows.push_str(&format!(
            r##"<tr><td><div class="font-medium">{name}</div><code class="text-xs opacity-50">{prefix}…</code></td>
            <td class="text-xs">@{owner}</td><td class="text-xs">{scopes}</td>
            <td class="text-xs">{last}</td><td class="text-xs">{exp}</td>
            <td>{status}</td><td class="text-right">{revoke}</td></tr>"##,
            name = html_escape(&t.name), prefix = html_escape(&t.token_prefix), owner = html_escape(&t.username),
            scopes = html_escape(&scopes), last = last, exp = exp, status = status, revoke = revoke,
        ));
    }
    if tokens.is_empty() {
        rows.push_str(r#"<tr><td colspan="7" class="text-center opacity-50 py-8">No API tokens yet.</td></tr>"#);
    }

    let inner = format!(
        r##"<div class="mb-4"><h1 class="text-2xl font-bold">API Tokens</h1>
<p class="text-base-content/60">Bearer credentials for the public REST API (<code>/api/v1</code>). A token acts as its owning user and inherits that user's roles. Send it as <code>Authorization: Bearer &lt;token&gt;</code> with header <code>X-Vortex-Database</code> naming the tenant.</p></div>
<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<h2 class="card-title text-lg">Create token</h2>
<form method="post" action="/settings/api-tokens" class="grid md:grid-cols-4 gap-3 items-end">
<label class="form-control"><span class="label-text">Name</span><input name="name" required placeholder="e.g. CI pipeline" class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text">Owner</span><select name="user_id" class="select select-bordered select-sm">{options}</select></label>
<label class="form-control"><span class="label-text">Expires (days, optional)</span><input name="expires_days" type="number" min="1" placeholder="never" class="input input-bordered input-sm"/></label>
<label class="label cursor-pointer gap-2 justify-start"><input type="checkbox" name="scope_write" value="1" class="checkbox checkbox-sm"/><span class="label-text">Allow writes</span></label>
<div class="md:col-span-4"><button class="btn btn-primary btn-sm">Create token</button></div>
</form></div></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<table class="table table-sm"><thead><tr><th>Token</th><th>Owner</th><th>Scopes</th><th>Last used</th><th>Expires</th><th>Status</th><th></th></tr></thead>
<tbody>{rows}</tbody></table></div></div>"##,
        options = options, rows = rows,
    );
    api_tokens_page_shell(&user, &inner).into_response()
}

#[derive(serde::Deserialize)]
struct ApiTokenForm {
    name: String,
    user_id: uuid::Uuid,
    expires_days: Option<String>,
    scope_write: Option<String>,
}

async fn api_token_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<ApiTokenForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("API Tokens"))).into_response();
    }
    let name = form.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Html(forbidden_page("API Tokens"))).into_response();
    }
    let scopes: Vec<String> = if form.scope_write.is_some() { vec!["write".into()] } else { vec![] };
    let expires_at = form
        .expires_days
        .as_deref()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|d| *d > 0)
        .map(|d| chrono::Utc::now() + chrono::Duration::days(d));

    let secret = match vortex_framework::api::create_token(
        &db, name, form.user_id, &scopes, expires_at, Some(user.id),
    ).await {
        Ok(s) => s,
        Err(e) => {
            return api_tokens_page_shell(
                &user,
                &format!(r#"<div class="alert alert-error">Failed to create token: {}</div><a href="/settings/api-tokens" class="btn btn-sm mt-4">Back</a>"#, html_escape(&e)),
            ).into_response();
        }
    };

    // Audit the mint (the secret itself is never logged).
    api_audit(
        &state, &db_ctx.db_name, &user,
        AuditAction::Custom("api_token_created".into()), AuditSeverity::Warning,
        "api_token", Some(&form.user_id.to_string()),
        serde_json::json!({"name": name, "scopes": scopes, "expires_at": expires_at}),
    ).await;

    // Show-once: the only time the secret is ever displayed.
    let inner = format!(
        r##"<div class="mb-4"><h1 class="text-2xl font-bold">Token created</h1></div>
<div class="alert alert-warning mb-4"><span>Copy this token now — it is shown <strong>once</strong> and cannot be retrieved again.</span></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<label class="label-text">Secret</label>
<div class="join w-full"><input id="tok" readonly value="{secret}" class="input input-bordered join-item w-full font-mono text-sm"/>
<button class="btn join-item" onclick="navigator.clipboard.writeText(document.getElementById('tok').value)">Copy</button></div>
<div class="mt-4"><label class="label-text">Example</label>
<pre class="bg-base-200 p-3 rounded text-xs overflow-x-auto">curl -H "Authorization: Bearer {secret}" \
     -H "X-Vortex-Database: {db}" \
     {scheme}/api/v1/whoami</pre></div>
<a href="/settings/api-tokens" class="btn btn-primary btn-sm mt-4 w-fit">Done</a>
</div></div>"##,
        secret = html_escape(&secret),
        db = html_escape(&db_ctx.db_name),
        scheme = "http://localhost:8080",
    );
    api_tokens_page_shell(&user, &inner).into_response()
}

async fn api_token_revoke(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("API Tokens"))).into_response();
    }
    let _ = vortex_framework::api::revoke_token(&db, id).await;
    api_audit(
        &state, &db_ctx.db_name, &user,
        AuditAction::Custom("api_token_revoked".into()), AuditSeverity::Warning,
        "api_token", Some(&id.to_string()), serde_json::json!({}),
    ).await;
    Redirect::to("/settings/api-tokens").into_response()
}

// ============================================================================
// Webhooks Management (outbound event subscriptions)
// ============================================================================

fn webhooks_page_shell(user: &AuthUser, title: &str, inner: &str) -> Html<String> {
    Html(format!(
        r##"<!DOCTYPE html><html lang="en" data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>{title} - Settings</title>
<link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="navbar bg-base-100 shadow-lg"><div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div><div class="flex-none"><span class="text-sm">@{user}</span></div></div>
<div class="container mx-auto p-6 max-w-4xl">{inner}</div></body></html>"##,
        title = html_escape(title), user = html_escape(&user.username), inner = inner,
    ))
}

// ═══════════════════════════════════════════════════════════════════════════
// Print layout designer — document branding (DocLayout) + per-document QWeb
// templates, on top of vortex_framework::print_layout. Admin-only.
// ═══════════════════════════════════════════════════════════════════════════

const LOGO_KEY_PL: &str = "company/logo";

/// Serve the uploaded company logo (used by the layout settings + preview).
async fn serve_company_logo(
    State(state): State<Arc<AppState>>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    match state.files.get(&db_ctx.db_name, LOGO_KEY_PL).await {
        Ok(Some(data)) => {
            let ct = if data.starts_with(&[0xFF, 0xD8, 0xFF]) { "image/jpeg" } else { "image/png" };
            ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, "no-cache")], data).into_response()
        }
        _ => (StatusCode::NOT_FOUND, "no logo").into_response(),
    }
}

async fn document_layout_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Document Layout"))).into_response();
    }
    let l = vortex_framework::print_layout::DocLayout::load(&db).await;
    let has_logo = matches!(state.files.get(&db_ctx.db_name, LOGO_KEY_PL).await, Ok(Some(_)));
    let logo_block = if has_logo {
        r#"<img src="/settings/company-logo" alt="logo" style="max-height:70px;max-width:240px" class="bg-white p-2 rounded border"/>"#.to_string()
    } else {
        r#"<span class="text-sm opacity-60">No logo uploaded yet.</span>"#.to_string()
    };
    let sel = |v: &str| if l.paper_size == v { "selected" } else { "" };
    let inner = format!(
        r##"<div class="mb-4"><a href="/settings/print-templates" class="link text-sm">→ Print templates</a>
<h1 class="text-2xl font-bold">Document Layout</h1>
<p class="text-base-content/60">Branding shared by every printed document (quotations, invoices…). Set the logo, colour, font and footer once; every document picks them up.</p></div>

<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<h2 class="card-title text-lg">Logo</h2>
<div class="flex items-center gap-4 flex-wrap">{logo_block}
<form method="post" action="/settings/document-layout/logo" enctype="multipart/form-data" class="flex items-center gap-2">
<input type="file" name="logo" accept="image/png,image/jpeg" required class="file-input file-input-bordered file-input-sm"/>
<button class="btn btn-primary btn-sm">Upload</button></form></div>
<p class="text-xs opacity-50 mt-2">PNG or JPEG, under 512 KB.</p></div></div>

<form method="post" action="/settings/document-layout" class="card bg-base-100 shadow"><div class="card-body grid md:grid-cols-2 gap-4">
<label class="form-control"><span class="label-text">Brand colour</span>
<input type="color" name="brand_color" value="{brand}" class="input input-bordered h-12 w-24 p-1"/></label>
<label class="form-control"><span class="label-text">Paper size</span>
<select name="paper_size" class="select select-bordered"><option {a4}>A4</option><option {lt}>Letter</option></select></label>
<label class="form-control md:col-span-2"><span class="label-text">Font family (CSS)</span>
<input name="font_family" value="{font}" class="input input-bordered"/></label>
<label class="form-control md:col-span-2"><span class="label-text">Footer (HTML) — shown at the bottom of every document</span>
<textarea name="footer_html" rows="2" class="textarea textarea-bordered">{footer}</textarea></label>
<div class="md:col-span-2"><button class="btn btn-primary">Save branding</button></div>
</div></form>"##,
        logo_block = logo_block,
        brand = html_escape(&l.brand_color),
        a4 = sel("A4"),
        lt = sel("Letter"),
        font = html_escape(&l.font_family),
        footer = html_escape(&l.footer_html),
    );
    webhooks_page_shell(&user, "Document Layout", &inner).into_response()
}

#[derive(serde::Deserialize)]
struct DocLayoutForm {
    brand_color: String,
    font_family: String,
    footer_html: String,
    paper_size: String,
}

async fn document_layout_save(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(f): Form<DocLayoutForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Document Layout"))).into_response();
    }
    let l = vortex_framework::print_layout::DocLayout {
        brand_color: f.brand_color,
        font_family: f.font_family,
        footer_html: f.footer_html,
        paper_size: f.paper_size,
    };
    let _ = l.save(&db, Some(user.id)).await;
    Redirect::to("/settings/document-layout").into_response()
}

async fn document_layout_logo(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    mut multipart: Multipart,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Document Layout"))).into_response();
    }
    let mut data: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("logo") {
            if let Ok(bytes) = field.bytes().await {
                data = Some(bytes.to_vec());
            }
        }
    }
    let Some(data) = data.filter(|d| !d.is_empty()) else {
        return Redirect::to("/settings/document-layout").into_response();
    };
    if data.len() > 512 * 1024 {
        return Redirect::to("/settings/document-layout").into_response();
    }
    let ct = if data.starts_with(&[0x89, b'P', b'N', b'G']) {
        "image/png"
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "image/jpeg"
    } else {
        return Redirect::to("/settings/document-layout").into_response();
    };
    let _ = state.files.put(&db_ctx.db_name, LOGO_KEY_PL, &data, Some(ct)).await;
    Redirect::to("/settings/document-layout").into_response()
}

async fn print_templates_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Print Templates"))).into_response();
    }
    let mut rows = String::new();
    for d in state.print_docs.all() {
        let custom = vortex_framework::print_layout::get_template(&db, &d.doc_type).await.is_some();
        let badge = if custom {
            r#"<span class="badge badge-success badge-sm">Customised</span>"#
        } else {
            r#"<span class="badge badge-ghost badge-sm">Default</span>"#
        };
        rows.push_str(&format!(
            r#"<tr><td><a href="/settings/print-templates/{dt}" class="link link-primary font-medium">{label}</a><div class="text-xs opacity-50">{dt}</div></td><td>{badge}</td><td class="text-right"><a href="/settings/print-templates/{dt}" class="btn btn-ghost btn-xs">Edit</a></td></tr>"#,
            dt = html_escape(&d.doc_type),
            label = html_escape(&d.label),
            badge = badge,
        ));
    }
    if state.print_docs.is_empty() {
        rows.push_str(r#"<tr><td colspan="3" class="text-center opacity-50 py-8">No printable documents are registered by the installed modules.</td></tr>"#);
    }
    let inner = format!(
        r##"<div class="mb-4"><a href="/settings/document-layout" class="link text-sm">→ Document layout (logo &amp; branding)</a>
<h1 class="text-2xl font-bold">Print Templates</h1>
<p class="text-base-content/60">Change how each printable document looks — no coding needed. Open one to use the <b>Visual editor</b> (toggle sections, pick columns, rename labels, live preview), or switch to the <b>HTML</b> tab for full control. Branding (logo, colour, footer) comes from the Document Layout page.</p></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<table class="table"><thead><tr><th>Document</th><th>Status</th><th></th></tr></thead><tbody>{rows}</tbody></table></div></div>"##,
        rows = rows,
    );
    webhooks_page_shell(&user, "Print Templates", &inner).into_response()
}

async fn print_template_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(doc_type): Path<String>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Print Templates"))).into_response();
    }
    let Some(d) = state.print_docs.get(&doc_type) else {
        return (StatusCode::NOT_FOUND, "Unknown document type").into_response();
    };
    let custom = vortex_framework::print_layout::get_template(&db, &doc_type).await;
    let is_custom = custom.is_some();
    let body = custom.unwrap_or_else(|| d.default_template.clone());
    let mut vars = String::new();
    for (k, v) in &d.variables {
        vars.push_str(&format!(
            r#"<tr><td class="font-mono text-xs align-top">{}</td><td class="text-xs">{}</td></tr>"#,
            html_escape(k),
            html_escape(v),
        ));
    }
    let status = if is_custom {
        r#"<span class="badge badge-success badge-sm align-middle">Customised</span>"#
    } else {
        r#"<span class="badge badge-ghost badge-sm align-middle">Using default</span>"#
    };
    let dt_esc = html_escape(&doc_type);

    // The advanced (raw-HTML) editor panel — always available.
    let html_panel = format!(
        r##"<form method="post" action="/settings/print-templates/{dt}/preview" target="_blank" id="tpl-form">
<div class="grid lg:grid-cols-3 gap-4">
<div class="lg:col-span-2 card bg-base-100 shadow"><div class="card-body">
<textarea name="body" id="tpl-body" rows="26" class="textarea textarea-bordered font-mono text-xs w-full" spellcheck="false">{body}</textarea>
<div class="flex gap-2 mt-3 flex-wrap">
<button formaction="/settings/print-templates/{dt}" formtarget="_self" class="btn btn-primary btn-sm" name="action" value="save">Save</button>
<button class="btn btn-outline btn-sm">Preview ↗</button>
<button type="button" class="btn btn-ghost btn-sm" onclick="document.getElementById('tpl-body').value=document.getElementById('tpl-default').textContent">Load default</button>
<button formaction="/settings/print-templates/{dt}" formtarget="_self" class="btn btn-ghost btn-sm text-error" name="action" value="reset" onclick="return confirm('Discard the custom template and use the built-in default?')">Reset to default</button>
</div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-sm">Available variables</h2>
<table class="table table-xs"><tbody>{vars}</tbody></table>
<p class="text-xs opacity-60 mt-2">Preview renders with sample data; the real print uses the record's data and your uploaded logo.</p>
</div></div>
</div></form>
<template id="tpl-default">{default}</template>"##,
        dt = dt_esc,
        body = html_escape(&body),
        vars = vars,
        default = html_escape(&d.default_template),
    );

    // The no-code Visual panel — only when the document exposes a config.
    let (tabs, panels, lead) = if let Some(base) = &d.default_config {
        // Which config populates the form: the saved visual state if any,
        // else the built-in starting config. If a custom body exists but has
        // no saved config, it was hand-edited in HTML — warn before overwrite.
        let saved_cfg =
            vortex_framework::print_layout::get_layout_config(&db, &doc_type).await;
        let hand_edited = is_custom && saved_cfg.is_none();
        let form_cfg = saved_cfg.unwrap_or_else(|| base.clone());
        let warn = if hand_edited {
            r#"<div class="alert alert-warning py-2 text-sm mb-3">This template was edited in the HTML tab. Saving from the Visual editor will replace those hand-made changes.</div>"#
        } else {
            ""
        };
        let form = render_visual_form(&form_cfg);
        let visual_panel = format!(
            r##"<div id="panel-visual">
{warn}
<form method="post" action="/settings/print-templates/{dt}/visual" id="vis-form">
<div class="grid lg:grid-cols-2 gap-4">
<div class="card bg-base-100 shadow"><div class="card-body max-h-[74vh] overflow-y-auto">
{form}
<div class="flex gap-2 mt-4 flex-wrap sticky bottom-0 bg-base-100 pt-3">
<button class="btn btn-primary btn-sm">Save</button>
<button formaction="/settings/print-templates/{dt}" formtarget="_self" class="btn btn-ghost btn-sm text-error" name="action" value="reset" onclick="return confirm('Discard customisations and use the built-in default?')">Reset to default</button>
</div>
</div></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="text-xs opacity-60 mb-2">Live preview — sample data</div>
<iframe id="vis-preview" title="Live preview" sandbox="allow-same-origin" class="w-full rounded border border-base-300 bg-white" style="height:74vh"></iframe>
</div></div>
</div></form>
</div>"##,
            warn = warn,
            dt = dt_esc,
            form = form,
        );
        let tabbar = r##"<div role="tablist" class="tabs tabs-boxed mb-4 w-fit">
<button type="button" id="tabbtn-visual" class="tab tab-active" data-panel="panel-visual">Visual editor</button>
<button type="button" id="tabbtn-html" class="tab" data-panel="panel-html">HTML (advanced)</button>
</div>"##
            .to_string();
        (
            tabbar,
            format!("{visual}<div id=\"panel-html\" style=\"display:none\">{html}</div>", visual = visual_panel, html = html_panel),
            "Toggle sections and edit labels on the left; the preview updates as you go. Switch to <b>HTML</b> for full control.",
        )
    } else {
        (
            String::new(),
            format!("<div id=\"panel-html\">{}</div>", html_panel),
            "Edit the HTML below and hit Preview to see it with sample data. Save to make it live; Reset restores the built-in default.",
        )
    };

    // Combined tab-switch + live-preview script (CSP: script-src 'self'
    // 'unsafe-inline'). No inline handlers on the tab buttons.
    let script = PRINT_EDITOR_JS.replace("__DT__", &doc_type.replace('"', ""));

    let inner = format!(
        r##"<div class="mb-4"><a href="/settings/print-templates" class="link text-sm">← Print templates</a>
<h1 class="text-2xl font-bold">{label} template {status}</h1>
<p class="text-base-content/60">{lead}</p></div>
{tabs}
{panels}
<script>{script}</script>"##,
        label = html_escape(&d.label),
        status = status,
        lead = lead,
        tabs = tabs,
        panels = panels,
        script = script,
    );
    webhooks_page_shell(&user, &d.label, &inner).into_response()
}

/// Client script for the print-template editor: tab switching and the Visual
/// editor's debounced live preview (posts the form, drops the returned HTML
/// into the preview iframe). `__DT__` is replaced with the document type.
const PRINT_EDITOR_JS: &str = r#"
(function(){
  var btns = document.querySelectorAll('[data-panel]');
  btns.forEach(function(b){
    b.addEventListener('click', function(){
      var target = b.getAttribute('data-panel');
      document.querySelectorAll('#panel-visual,#panel-html').forEach(function(p){
        p.style.display = (p.id === target) ? '' : 'none';
      });
      btns.forEach(function(x){ x.classList.toggle('tab-active', x === b); });
    });
  });
  var form = document.getElementById('vis-form');
  var frame = document.getElementById('vis-preview');
  if(form && frame){
    var url = '/settings/print-templates/__DT__/visual/preview';
    var t;
    function refresh(){
      var data = new URLSearchParams(new FormData(form));
      fetch(url, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:data.toString()})
        .then(function(r){ return r.text(); })
        .then(function(html){ frame.srcdoc = html; })
        .catch(function(){});
    }
    form.addEventListener('input', function(){ clearTimeout(t); t=setTimeout(refresh, 250); });
    form.addEventListener('change', function(){ clearTimeout(t); t=setTimeout(refresh, 250); });
    refresh();
  }
})();
"#;

#[derive(serde::Deserialize)]
struct PrintTplForm {
    body: Option<String>,
    action: Option<String>,
}

async fn print_template_save(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(doc_type): Path<String>,
    Form(f): Form<PrintTplForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Print Templates"))).into_response();
    }
    if state.print_docs.get(&doc_type).is_none() {
        return (StatusCode::NOT_FOUND, "Unknown document type").into_response();
    }
    let body = f.body.unwrap_or_default();
    if f.action.as_deref() == Some("reset") || body.trim().is_empty() {
        let _ = vortex_framework::print_layout::clear_template(&db, &doc_type).await;
    } else {
        let _ = vortex_framework::print_layout::save_template(&db, &doc_type, &body, Some(user.id)).await;
    }
    Redirect::to(&format!("/settings/print-templates/{}", doc_type)).into_response()
}

async fn print_template_preview(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(doc_type): Path<String>,
    Form(f): Form<PrintTplForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Print Templates"))).into_response();
    }
    let Some(d) = state.print_docs.get(&doc_type) else {
        return (StatusCode::NOT_FOUND, "Unknown document type").into_response();
    };
    let layout = vortex_framework::print_layout::DocLayout::load(&db).await;
    let body = f.body.unwrap_or_default();
    let body = if body.trim().is_empty() { d.default_template.clone() } else { body };
    let mut globals = d.sample_globals.clone();
    if matches!(state.files.get(&db_ctx.db_name, LOGO_KEY_PL).await, Ok(Some(_))) {
        globals.insert("company.logo".into(), "/settings/company-logo".into());
    }
    let title = format!("{} (preview)", d.label);
    let html = vortex_framework::print_layout::render_body(&layout, &title, &body, &globals, &d.sample_lines);
    Html(html).into_response()
}

/// Render the no-code Visual editor form from a [`LayoutConfig`]. Every control
/// carries the field name that [`layout_config_from_form`] reads back.
fn render_visual_form(cfg: &vortex_framework::print_layout::LayoutConfig) -> String {
    let cbx = |name: &str, label: &str, checked: bool| -> String {
        format!(
            r#"<label class="label cursor-pointer justify-start gap-3 py-1"><input type="checkbox" name="{n}" class="checkbox checkbox-sm" {c}/><span class="label-text">{l}</span></label>"#,
            n = name,
            c = if checked { "checked" } else { "" },
            l = html_escape(label),
        )
    };
    let txt = |name: &str, label: &str, value: &str| -> String {
        format!(
            r#"<label class="form-control w-full"><span class="label-text text-xs opacity-70">{l}</span><input type="text" name="{n}" value="{v}" class="input input-bordered input-sm w-full" maxlength="80"/></label>"#,
            n = name,
            l = html_escape(label),
            v = html_escape(value),
        )
    };
    let section = |title: &str, body: &str| -> String {
        format!(
            r#"<div class="mb-4"><div class="text-xs font-semibold uppercase tracking-wide opacity-50 mb-1 border-b border-base-300 pb-1">{t}</div>{b}</div>"#,
            t = html_escape(title),
            b = body,
        )
    };

    // Header
    let header = format!(
        "{title}{logo}{addr}{reg}<div class=\"mt-2 grid grid-cols-1 gap-1\">{num}{date}{val}</div>{vallbl}",
        title = txt("title", "Document title", &cfg.title),
        logo = cbx("show_logo", "Show company logo", cfg.show_logo),
        addr = cbx("show_company_address", "Show company address", cfg.show_company_address),
        reg = cbx("show_company_reg", "Show company registration no.", cfg.show_company_reg),
        num = cbx("show_number", "Show document number", cfg.show_number),
        date = cbx("show_date", "Show date", cfg.show_date),
        val = cbx("show_validity", "Show validity / due date", cfg.show_validity),
        vallbl = txt("validity_label", "Validity row label", &cfg.validity_label),
    );

    // Customer
    let customer = format!(
        "{show}{label}",
        show = cbx("show_customer", "Show bill-to / customer block", cfg.show_customer),
        label = txt("customer_label", "Bill-to label", &cfg.customer_label),
    );

    // Columns
    let mut cols = String::from(r#"<div class="text-xs opacity-60 mb-2">Tick a column to show it; edit its heading.</div>"#);
    for c in &cfg.columns {
        cols.push_str(&format!(
            r#"<div class="flex items-center gap-2 mb-1">{show}<input type="text" name="col_label_{key}" value="{label}" class="input input-bordered input-xs flex-1" maxlength="40"/><span class="badge badge-ghost badge-xs font-mono">{key}</span></div>"#,
            show = cbx(&format!("col_show_{}", c.key), "", c.show),
            key = html_escape(&c.key),
            label = html_escape(&c.label),
        ));
    }

    // Totals
    let totals = format!(
        "{sub}{subl}{tax}{taxl}{totl}",
        sub = cbx("show_subtotal", "Show subtotal row", cfg.show_subtotal),
        subl = txt("subtotal_label", "Subtotal label", &cfg.subtotal_label),
        tax = cbx("show_tax", "Show tax row", cfg.show_tax),
        taxl = txt("tax_label", "Tax label", &cfg.tax_label),
        totl = txt("total_label", "Total label", &cfg.total_label),
    );

    // Notes & signatures
    let notes = format!(
        "{n}{nl}{s}{sl}{sr}",
        n = cbx("show_notes", "Show notes block", cfg.show_notes),
        nl = txt("notes_label", "Notes heading", &cfg.notes_label),
        s = cbx("show_signatures", "Show signature strip", cfg.show_signatures),
        sl = txt("sign_left", "Left signature label", &cfg.sign_left),
        sr = txt("sign_right", "Right signature label", &cfg.sign_right),
    );

    format!(
        "{}{}{}{}{}",
        section("Header", &header),
        section("Bill-to", &customer),
        section("Line columns", &cols),
        section("Totals", &totals),
        section("Notes &amp; signatures", &notes),
    )
}

/// Build a [`LayoutConfig`] from the submitted Visual-editor form. Column keys
/// and order come from `base` (plugin-defined); the form only overrides the
/// `show` flag and the label of each. Absent checkbox names mean unchecked.
fn layout_config_from_form(
    base: &vortex_framework::print_layout::LayoutConfig,
    f: &std::collections::HashMap<String, String>,
) -> vortex_framework::print_layout::LayoutConfig {
    let has = |k: &str| f.contains_key(k);
    let txt = |k: &str, d: &str| {
        f.get(k)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| d.to_string())
    };
    let mut cfg = base.clone();
    cfg.title = txt("title", &base.title);
    cfg.show_logo = has("show_logo");
    cfg.show_company_address = has("show_company_address");
    cfg.show_company_reg = has("show_company_reg");
    cfg.show_customer = has("show_customer");
    cfg.customer_label = txt("customer_label", &base.customer_label);
    cfg.show_number = has("show_number");
    cfg.show_date = has("show_date");
    cfg.show_validity = has("show_validity");
    cfg.validity_label = txt("validity_label", &base.validity_label);
    cfg.show_subtotal = has("show_subtotal");
    cfg.show_tax = has("show_tax");
    cfg.subtotal_label = txt("subtotal_label", &base.subtotal_label);
    cfg.tax_label = txt("tax_label", &base.tax_label);
    cfg.total_label = txt("total_label", &base.total_label);
    cfg.show_notes = has("show_notes");
    cfg.notes_label = txt("notes_label", &base.notes_label);
    cfg.show_signatures = has("show_signatures");
    cfg.sign_left = txt("sign_left", &base.sign_left);
    cfg.sign_right = txt("sign_right", &base.sign_right);
    for (i, col) in base.columns.iter().enumerate() {
        cfg.columns[i].show = has(&format!("col_show_{}", col.key));
        cfg.columns[i].label = txt(&format!("col_label_{}", col.key), &col.label);
    }
    cfg
}

async fn print_template_visual_save(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(doc_type): Path<String>,
    Form(f): Form<std::collections::HashMap<String, String>>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Print Templates"))).into_response();
    }
    let Some(d) = state.print_docs.get(&doc_type) else {
        return (StatusCode::NOT_FOUND, "Unknown document type").into_response();
    };
    let Some(base) = &d.default_config else {
        return (StatusCode::BAD_REQUEST, "This document has no visual editor").into_response();
    };
    let cfg = layout_config_from_form(base, &f);
    let _ = vortex_framework::print_layout::save_layout(&db, &doc_type, &cfg, Some(user.id)).await;
    Redirect::to(&format!("/settings/print-templates/{}", doc_type)).into_response()
}

async fn print_template_visual_preview(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(doc_type): Path<String>,
    Form(f): Form<std::collections::HashMap<String, String>>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Print Templates"))).into_response();
    }
    let Some(d) = state.print_docs.get(&doc_type) else {
        return (StatusCode::NOT_FOUND, "Unknown document type").into_response();
    };
    let Some(base) = &d.default_config else {
        return (StatusCode::BAD_REQUEST, "This document has no visual editor").into_response();
    };
    let cfg = layout_config_from_form(base, &f);
    let body = vortex_framework::print_layout::build_template(&cfg);
    let layout = vortex_framework::print_layout::DocLayout::load(&db).await;
    let mut globals = d.sample_globals.clone();
    if matches!(state.files.get(&db_ctx.db_name, LOGO_KEY_PL).await, Ok(Some(_))) {
        globals.insert("company.logo".into(), "/settings/company-logo".into());
    }
    let title = format!("{} (preview)", d.label);
    let html = vortex_framework::print_layout::render_body(&layout, &title, &body, &globals, &d.sample_lines);
    Html(html).into_response()
}

/// Comma/space/newline separated event types -> Vec, empty -> [] (all events).
fn parse_event_types(raw: &str) -> Vec<String> {
    raw.split([',', '\n', ' ', '\t'])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

async fn webhooks_list(Db(db): Db, Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Webhooks"))).into_response();
    }
    let endpoints = vortex_framework::webhooks::list_endpoints(&db).await;
    let mut rows = String::new();
    for e in &endpoints {
        let events = if e.event_types.is_empty() { "all events".to_string() } else { e.event_types.join(", ") };
        let active = if e.active { r#"<span class="badge badge-success badge-sm">active</span>"# } else { r#"<span class="badge badge-ghost badge-sm">paused</span>"# };
        let last = match (&e.last_status, e.last_delivery_at) {
            (Some(s), Some(t)) => {
                let badge = if s == "success" { "badge-success" } else { "badge-error" };
                format!(r#"<span class="badge {badge} badge-xs">{s}</span> <span class="text-xs opacity-50">{}</span>"#, t.format("%Y-%m-%d %H:%M"))
            }
            _ => r#"<span class="opacity-40 text-xs">never</span>"#.to_string(),
        };
        rows.push_str(&format!(
            r##"<tr><td><a href="/settings/webhooks/{id}" class="link link-primary font-medium">{name}</a><div class="text-xs opacity-50 truncate max-w-xs">{url}</div></td>
            <td class="text-xs">{events}</td><td>{active}</td><td>{last}</td></tr>"##,
            id = e.id, name = html_escape(&e.name), url = html_escape(&e.url),
            events = html_escape(&events), active = active, last = last,
        ));
    }
    if endpoints.is_empty() {
        rows.push_str(r#"<tr><td colspan="4" class="text-center opacity-50 py-8">No webhook endpoints.</td></tr>"#);
    }
    let inner = format!(
        r##"<div class="mb-4"><h1 class="text-2xl font-bold">Webhooks</h1>
<p class="text-base-content/60">Subscribe external systems to events. Deliveries ride the durable job queue (retries, backoff, dead-letter) and are signed with <code>X-Vortex-Signature: sha256=HMAC(secret, body)</code>. Core events: <code>record.created</code>, <code>record.updated</code>, <code>record.deleted</code>.</p></div>
<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<h2 class="card-title text-lg">Add endpoint</h2>
<form method="post" action="/settings/webhooks" class="grid md:grid-cols-2 gap-3">
<label class="form-control"><span class="label-text">Name</span><input name="name" required class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text">Payload URL</span><input name="url" type="url" required placeholder="https://example.com/hook" class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text">Signing secret (optional)</span><input name="secret" class="input input-bordered input-sm" placeholder="whsec_…"/></label>
<label class="form-control"><span class="label-text">Event types (comma-sep, blank = all)</span><input name="event_types" class="input input-bordered input-sm" placeholder="record.created, record.deleted"/></label>
<div class="md:col-span-2"><button class="btn btn-primary btn-sm">Add endpoint</button></div>
</form></div></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<table class="table table-sm"><thead><tr><th>Endpoint</th><th>Events</th><th>Status</th><th>Last delivery</th></tr></thead>
<tbody>{rows}</tbody></table></div></div>"##,
        rows = rows,
    );
    webhooks_page_shell(&user, "Webhooks", &inner).into_response()
}

#[derive(serde::Deserialize)]
struct WebhookForm {
    name: String,
    url: String,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    event_types: String,
    #[serde(default)]
    active: Option<String>,
}

async fn webhook_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<WebhookForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Webhooks"))).into_response();
    }
    let events = parse_event_types(&form.event_types);
    match vortex_framework::webhooks::create_endpoint(
        &db, form.name.trim(), form.url.trim(), &form.secret, &events, Some(user.id),
    ).await {
        Ok(id) => {
            api_audit(&state, &db_ctx.db_name, &user,
                AuditAction::Custom("webhook_created".into()), AuditSeverity::Info,
                "webhook_endpoint", Some(&id.to_string()),
                serde_json::json!({"url": form.url.trim(), "event_types": events})).await;
            Redirect::to("/settings/webhooks").into_response()
        }
        Err(e) => webhooks_page_shell(&user, "Webhooks",
            &format!(r#"<div class="alert alert-error">Failed: {}</div><a href="/settings/webhooks" class="btn btn-sm mt-4">Back</a>"#, html_escape(&e))).into_response(),
    }
}

async fn webhook_edit(Db(db): Db, Extension(user): Extension<AuthUser>, Path(id): Path<uuid::Uuid>) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Webhooks"))).into_response();
    }
    let Some(e) = vortex_framework::webhooks::get_endpoint(&db, id).await else {
        return (StatusCode::NOT_FOUND, Html(forbidden_page("Webhooks"))).into_response();
    };
    let deliveries = vortex_framework::webhooks::recent_deliveries(&db, id, 20).await;
    let mut drows = String::new();
    for d in &deliveries {
        let st = d.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let badge = if st == "success" { "badge-success" } else { "badge-error" };
        drows.push_str(&format!(
            r##"<tr><td class="text-xs"><code>{ev}</code></td><td><span class="badge {badge} badge-xs">{st}</span></td>
            <td class="text-xs">{code}</td><td class="text-xs">{ms}ms</td><td class="text-xs opacity-50">{at}</td>
            <td class="text-xs text-error">{err}</td></tr>"##,
            ev = html_escape(d.get("event_type").and_then(|v| v.as_str()).unwrap_or("")),
            badge = badge, st = html_escape(st),
            code = d.get("status_code").and_then(|v| v.as_i64()).map(|c| c.to_string()).unwrap_or_else(|| "—".into()),
            ms = d.get("duration_ms").and_then(|v| v.as_i64()).unwrap_or(0),
            at = html_escape(d.get("created_at").and_then(|v| v.as_str()).unwrap_or("")),
            err = html_escape(d.get("error").and_then(|v| v.as_str()).unwrap_or("")),
        ));
    }
    if deliveries.is_empty() {
        drows.push_str(r#"<tr><td colspan="6" class="text-center opacity-50 py-6">No deliveries yet.</td></tr>"#);
    }
    let events_val = e.event_types.join(", ");
    let checked = if e.active { "checked" } else { "" };
    let inner = format!(
        r##"<div class="mb-4"><a href="/settings/webhooks" class="btn btn-ghost btn-sm">← Webhooks</a><h1 class="text-2xl font-bold mt-2">{name}</h1></div>
<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<form method="post" action="/settings/webhooks/{id}" class="grid md:grid-cols-2 gap-3">
<label class="form-control"><span class="label-text">Name</span><input name="name" required value="{name}" class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text">Payload URL</span><input name="url" type="url" required value="{url}" class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text">Signing secret (blank = keep)</span><input name="secret" class="input input-bordered input-sm" placeholder="•••• unchanged"/></label>
<label class="form-control"><span class="label-text">Event types (blank = all)</span><input name="event_types" value="{events}" class="input input-bordered input-sm"/></label>
<label class="label cursor-pointer gap-2 justify-start"><input type="checkbox" name="active" value="1" {checked} class="checkbox checkbox-sm"/><span class="label-text">Active</span></label>
<div class="md:col-span-2 flex gap-2"><button class="btn btn-primary btn-sm">Save</button></div>
</form>
<div class="flex gap-2 mt-2 pt-3 border-t border-base-300">
<form method="post" action="/settings/webhooks/{id}/test"><button class="btn btn-outline btn-sm">Send test event</button></form>
<form method="post" action="/settings/webhooks/{id}/delete" onsubmit="return confirm('Delete this endpoint?')"><button class="btn btn-error btn-outline btn-sm">Delete</button></form>
</div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg">Recent deliveries</h2>
<table class="table table-sm"><thead><tr><th>Event</th><th>Status</th><th>Code</th><th>Time</th><th>At</th><th>Error</th></tr></thead>
<tbody>{drows}</tbody></table></div></div>"##,
        id = e.id, name = html_escape(&e.name), url = html_escape(&e.url),
        events = html_escape(&events_val), checked = checked, drows = drows,
    );
    webhooks_page_shell(&user, &e.name, &inner).into_response()
}

async fn webhook_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<WebhookForm>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Webhooks"))).into_response();
    }
    let events = parse_event_types(&form.event_types);
    let active = form.active.is_some();
    let _ = vortex_framework::webhooks::update_endpoint(
        &db, id, form.name.trim(), form.url.trim(), &form.secret, &events, active,
    ).await;
    api_audit(&state, &db_ctx.db_name, &user,
        AuditAction::Custom("webhook_updated".into()), AuditSeverity::Info,
        "webhook_endpoint", Some(&id.to_string()), serde_json::json!({"active": active})).await;
    Redirect::to(&format!("/settings/webhooks/{id}")).into_response()
}

async fn webhook_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Webhooks"))).into_response();
    }
    let _ = vortex_framework::webhooks::delete_endpoint(&db, id).await;
    api_audit(&state, &db_ctx.db_name, &user,
        AuditAction::Custom("webhook_deleted".into()), AuditSeverity::Warning,
        "webhook_endpoint", Some(&id.to_string()), serde_json::json!({})).await;
    Redirect::to("/settings/webhooks").into_response()
}

/// Enqueue a `webhook.ping` test event to a single endpoint (bypasses the
/// subscription filter so an operator can verify connectivity).
async fn webhook_test(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Webhooks"))).into_response();
    }
    if vortex_framework::webhooks::get_endpoint(&db, id).await.is_some() {
        let job = vortex_framework::NewJob::new(
            vortex_framework::webhooks::DELIVER_KIND,
            serde_json::json!({"endpoint_id": id, "event_type": "ping", "data": {"message": "Test event from Vortex"}}),
        ).for_db(&db_ctx.db_name).trace("webhook_endpoint", &id.to_string());
        let _ = vortex_framework::jobs::enqueue(&state.db, job).await;
    }
    Redirect::to(&format!("/settings/webhooks/{id}")).into_response()
}

// ============================================================================
// Sequences Management
// ============================================================================

async fn sequences_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let sequences = sqlx::query(
        "SELECT id, name, code, prefix, suffix, padding, number_next, number_increment, reset_period, use_date_range, date_format
         FROM ir_sequence WHERE active = true ORDER BY name"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows_html = String::new();
    for seq in &sequences {
        let id: uuid::Uuid = seq.get("id");
        let name: String = seq.get("name");
        let code: String = seq.get("code");
        let prefix: Option<String> = seq.get("prefix");
        let suffix: Option<String> = seq.get("suffix");
        let padding: i32 = seq.get("padding");
        let number_next: i32 = seq.get("number_next");
        let reset_period: Option<String> = seq.get("reset_period");
        let use_date_range: bool = seq.get("use_date_range");
        let date_format: Option<String> = seq.get("date_format");

        // Build preview
        let mut preview = prefix.clone().unwrap_or_default();
        if use_date_range {
            preview.push_str(&date_format.clone().unwrap_or_else(|| "YYYY".to_string()));
            preview.push('-');
        }
        preview.push_str(&"0".repeat(padding as usize - 1));
        preview.push('1');
        if let Some(s) = &suffix {
            preview.push_str(s);
        }

        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/sequences/{}" class="link link-primary">{}</a></td>
                <td><code class="text-sm">{}</code></td>
                <td><code class="text-xs bg-base-200 px-2 py-1 rounded">{}</code></td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>"##,
            id, name, code, preview, number_next,
            reset_period.unwrap_or_else(|| "never".to_string()),
            if use_date_range { "Yes" } else { "No" }
        ));
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sequences - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
    <script src="/static/vendor/htmx.min.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Sequences</h1>
                <p class="text-base-content/60">Auto-numbering for documents</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Sequence</button>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Code</th>
                            <th>Preview</th>
                            <th>Next #</th>
                            <th>Reset</th>
                            <th>Date Range</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4">
            <a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a>
        </div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New Sequence</h3>
            <form method="post" action="/settings/sequences">
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" placeholder="e.g., Invoice" required/>
                </div>
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Code</span></label>
                    <input type="text" name="code" class="input input-bordered" placeholder="e.g., work.order" required/>
                    <label class="label"><span class="label-text-alt">Unique identifier used in API</span></label>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Prefix</span></label>
                        <input type="text" name="prefix" class="input input-bordered" placeholder="e.g., WO-"/>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Suffix</span></label>
                        <input type="text" name="suffix" class="input input-bordered" placeholder="e.g., -A"/>
                    </div>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Padding</span></label>
                        <input type="number" name="padding" class="input input-bordered" value="5" min="1" max="10"/>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Start Number</span></label>
                        <input type="number" name="number_next" class="input input-bordered" value="1" min="1"/>
                    </div>
                </div>
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Reset Period</span></label>
                    <select name="reset_period" class="select select-bordered">
                        <option value="never">Never</option>
                        <option value="year">Yearly</option>
                        <option value="month">Monthly</option>
                    </select>
                </div>
                <div class="form-control mb-3">
                    <label class="label cursor-pointer justify-start gap-3">
                        <input type="checkbox" name="use_date_range" class="checkbox"/>
                        <span class="label-text">Include date in sequence</span>
                    </label>
                </div>
                <div class="form-control mb-4">
                    <label class="label"><span class="label-text">Date Format</span></label>
                    <select name="date_format" class="select select-bordered">
                        <option value="YYYY">YYYY (2026)</option>
                        <option value="YYYYMM">YYYYMM (202602)</option>
                        <option value="YYMM">YYMM (2602)</option>
                    </select>
                </div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user.username, rows_html
    );

    Html(html).into_response()
}

#[derive(Debug, serde::Deserialize)]
struct SequenceForm {
    name: String,
    code: Option<String>,  // Optional for updates
    prefix: Option<String>,
    suffix: Option<String>,
    padding: Option<i32>,
    number_next: Option<i32>,
    reset_period: Option<String>,
    use_date_range: Option<String>,
    date_format: Option<String>,
}

async fn sequence_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Form(form): Form<SequenceForm>,
) -> Response {
    let Some(code) = form.code else {
        return (StatusCode::BAD_REQUEST, "Code is required").into_response();
    };

    let use_date = form.use_date_range.is_some();
    let reset = if form.reset_period.as_deref() == Some("never") { None } else { form.reset_period };

    let _ = sqlx::query(
        "INSERT INTO ir_sequence (name, code, prefix, suffix, padding, number_next, reset_period, use_date_range, date_format)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    )
    .bind(&form.name)
    .bind(&code)
    .bind(&form.prefix)
    .bind(&form.suffix)
    .bind(form.padding.unwrap_or(5))
    .bind(form.number_next.unwrap_or(1))
    .bind(&reset)
    .bind(use_date)
    .bind(&form.date_format)
    .execute(&db)
    .await;

    Redirect::to("/settings/sequences").into_response()
}

async fn sequence_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let seq = sqlx::query(
        "SELECT id, name, code, prefix, suffix, padding, number_next, number_increment, reset_period, use_date_range, date_format
         FROM ir_sequence WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(seq) = seq else {
        return Redirect::to("/settings/sequences").into_response();
    };

    let name: String = seq.get("name");
    let code: String = seq.get("code");
    let prefix: Option<String> = seq.get("prefix");
    let suffix: Option<String> = seq.get("suffix");
    let padding: i32 = seq.get("padding");
    let number_next: i32 = seq.get("number_next");
    let reset_period: Option<String> = seq.get("reset_period");
    let use_date_range: bool = seq.get("use_date_range");
    let date_format: Option<String> = seq.get("date_format");

    let reset_never = if reset_period.is_none() { " selected" } else { "" };
    let reset_year = if reset_period.as_deref() == Some("year") { " selected" } else { "" };
    let reset_month = if reset_period.as_deref() == Some("month") { " selected" } else { "" };

    let df_yyyy = if date_format.as_deref() == Some("YYYY") || date_format.is_none() { " selected" } else { "" };
    let df_yyyymm = if date_format.as_deref() == Some("YYYYMM") { " selected" } else { "" };
    let df_yymm = if date_format.as_deref() == Some("YYMM") { " selected" } else { "" };

    let checked = if use_date_range { " checked" } else { "" };

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Sequence</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-2xl">
        <div class="mb-6">
            <a href="/settings/sequences" class="btn btn-ghost btn-sm">← Back to Sequences</a>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body">
                <h2 class="card-title">{}</h2>
                <p class="text-base-content/60 mb-4">Code: <code>{}</code></p>

                <form method="post" action="/settings/sequences/{}">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Name</span></label>
                        <input type="text" name="name" class="input input-bordered" value="{}" required/>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Prefix</span></label>
                            <input type="text" name="prefix" class="input input-bordered" value="{}"/>
                        </div>
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Suffix</span></label>
                            <input type="text" name="suffix" class="input input-bordered" value="{}"/>
                        </div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Padding</span></label>
                            <input type="number" name="padding" class="input input-bordered" value="{}" min="1" max="10"/>
                        </div>
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Next Number</span></label>
                            <input type="number" name="number_next" class="input input-bordered" value="{}" min="1"/>
                        </div>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Reset Period</span></label>
                        <select name="reset_period" class="select select-bordered">
                            <option value="never"{}>Never</option>
                            <option value="year"{}>Yearly</option>
                            <option value="month"{}>Monthly</option>
                        </select>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label cursor-pointer justify-start gap-3">
                            <input type="checkbox" name="use_date_range" class="checkbox"{}>
                            <span class="label-text">Include date in sequence</span>
                        </label>
                    </div>
                    <div class="form-control mb-4">
                        <label class="label"><span class="label-text">Date Format</span></label>
                        <select name="date_format" class="select select-bordered">
                            <option value="YYYY"{}>YYYY (2026)</option>
                            <option value="YYYYMM"{}>YYYYMM (202602)</option>
                            <option value="YYMM"{}>YYMM (2602)</option>
                        </select>
                    </div>
                    <div class="card-actions justify-end">
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html>"##,
        name, user.username, name, code, id, name,
        prefix.unwrap_or_default(), suffix.unwrap_or_default(),
        padding, number_next,
        reset_never, reset_year, reset_month,
        checked,
        df_yyyy, df_yyyymm, df_yymm
    );

    Html(html).into_response()
}

async fn sequence_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<SequenceForm>,
) -> Response {
    let use_date = form.use_date_range.is_some();
    let reset = if form.reset_period.as_deref() == Some("never") { None } else { form.reset_period };

    let _ = sqlx::query(
        "UPDATE ir_sequence SET name = $1, prefix = $2, suffix = $3, padding = $4, number_next = $5, reset_period = $6, use_date_range = $7, date_format = $8, updated_at = NOW()
         WHERE id = $9"
    )
    .bind(&form.name)
    .bind(&form.prefix)
    .bind(&form.suffix)
    .bind(form.padding.unwrap_or(5))
    .bind(form.number_next.unwrap_or(1))
    .bind(&reset)
    .bind(use_date)
    .bind(&form.date_format)
    .bind(id)
    .execute(&db)
    .await;

    Redirect::to("/settings/sequences").into_response()
}

// ============================================================================
// Cron Jobs Management
// ============================================================================

async fn cron_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let crons = sqlx::query(
        "SELECT id, name, function_name, interval_number, interval_type, next_run_at, last_run_at, last_run_status, active
         FROM ir_cron ORDER BY priority, name"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows_html = String::new();
    for cron in &crons {
        let id: uuid::Uuid = cron.get("id");
        let name: String = cron.get("name");
        let function_name: String = cron.get("function_name");
        let interval_number: i32 = cron.get("interval_number");
        let interval_type: String = cron.get("interval_type");
        let next_run_at: Option<chrono::DateTime<chrono::Utc>> = cron.get("next_run_at");
        let last_run_at: Option<chrono::DateTime<chrono::Utc>> = cron.get("last_run_at");
        let last_run_status: Option<String> = cron.get("last_run_status");
        let active: bool = cron.get("active");

        let schedule = format!("Every {} {}", interval_number, interval_type);
        let next_run = next_run_at.map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let last_run = last_run_at.map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "Never".to_string());

        let status_badge = match last_run_status.as_deref() {
            Some("success") => r#"<span class="badge badge-success badge-sm">Success</span>"#,
            Some("error") => r#"<span class="badge badge-error badge-sm">Error</span>"#,
            Some("running") => r#"<span class="badge badge-warning badge-sm">Running</span>"#,
            _ => r#"<span class="badge badge-ghost badge-sm">-</span>"#,
        };

        let active_badge = if active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else {
            r#"<span class="badge badge-ghost badge-sm">Inactive</span>"#
        };

        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/cron/{}" class="link link-primary">{}</a></td>
                <td><code class="text-xs">{}</code></td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>
                    <form method="post" action="/settings/cron/{}/run" class="inline">
                        <button type="submit" class="btn btn-ghost btn-xs" title="Run Now">▶</button>
                    </form>
                    <form method="post" action="/settings/cron/{}/toggle" class="inline">
                        <button type="submit" class="btn btn-ghost btn-xs" title="Toggle">{}</button>
                    </form>
                </td>
            </tr>"##,
            id, name, function_name, schedule, next_run, last_run, status_badge, active_badge,
            id, id,
            if active { "⏸" } else { "▶" }
        ));
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scheduled Jobs - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
    <script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Scheduled Jobs</h1>
                <p class="text-base-content/60">Background task scheduling</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Job</button>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Function</th>
                            <th>Schedule</th>
                            <th>Next Run</th>
                            <th>Last Run</th>
                            <th>Status</th>
                            <th>Active</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4">
            <a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a>
        </div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New Scheduled Job</h3>
            <form method="post" action="/settings/cron">
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" placeholder="e.g., Daily Report" required/>
                </div>
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Function</span></label>
                    <input type="text" name="function_name" class="input input-bordered" placeholder="e.g., send_daily_report" required/>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Every</span></label>
                        <input type="number" name="interval_number" class="input input-bordered" value="1" min="1"/>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Period</span></label>
                        <select name="interval_type" class="select select-bordered">
                            <option value="minutes">Minutes</option>
                            <option value="hours">Hours</option>
                            <option value="days" selected>Days</option>
                            <option value="weeks">Weeks</option>
                            <option value="months">Months</option>
                        </select>
                    </div>
                </div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user.username, rows_html
    );

    Html(html).into_response()
}

#[derive(Debug, serde::Deserialize)]
struct CronForm {
    name: String,
    function_name: String,
    interval_number: Option<i32>,
    interval_type: Option<String>,
    priority: Option<i32>,
}

async fn cron_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Form(form): Form<CronForm>,
) -> Response {
    let interval_number = form.interval_number.unwrap_or(1);
    let interval_type = form.interval_type.as_deref().unwrap_or("days");

    // Calculate next run time
    let next_run = match interval_type {
        "minutes" => chrono::Utc::now() + chrono::Duration::minutes(interval_number as i64),
        "hours" => chrono::Utc::now() + chrono::Duration::hours(interval_number as i64),
        "days" => chrono::Utc::now() + chrono::Duration::days(interval_number as i64),
        "weeks" => chrono::Utc::now() + chrono::Duration::weeks(interval_number as i64),
        "months" => chrono::Utc::now() + chrono::Duration::days(interval_number as i64 * 30),
        _ => chrono::Utc::now() + chrono::Duration::days(1),
    };

    let _ = sqlx::query(
        "INSERT INTO ir_cron (name, function_name, interval_number, interval_type, next_run_at, priority)
         VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(&form.name)
    .bind(&form.function_name)
    .bind(interval_number)
    .bind(interval_type)
    .bind(next_run)
    .bind(form.priority.unwrap_or(10))
    .execute(&db)
    .await;

    Redirect::to("/settings/cron").into_response()
}

async fn cron_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let cron = sqlx::query(
        "SELECT id, name, function_name, interval_number, interval_type, next_run_at, last_run_at, last_run_status, last_run_message, priority, active
         FROM ir_cron WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(cron) = cron else {
        return Redirect::to("/settings/cron").into_response();
    };

    let name: String = cron.get("name");
    let function_name: String = cron.get("function_name");
    let interval_number: i32 = cron.get("interval_number");
    let interval_type: String = cron.get("interval_type");
    let priority: i32 = cron.get("priority");
    let active: bool = cron.get("active");
    let last_run_message: Option<String> = cron.get("last_run_message");

    let interval_options = ["minutes", "hours", "days", "weeks", "months"];
    let interval_select: String = interval_options.iter().map(|opt| {
        let selected = if *opt == interval_type { " selected" } else { "" };
        format!(r#"<option value="{}"{}>{}  </option>"#, opt, selected, opt.chars().next().unwrap().to_uppercase().to_string() + &opt[1..])
    }).collect();

    // Fetch recent logs
    let logs = sqlx::query(
        "SELECT started_at, finished_at, status, message, records_processed
         FROM ir_cron_log WHERE cron_id = $1 ORDER BY started_at DESC LIMIT 10"
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut logs_html = String::new();
    for log in &logs {
        let started_at: chrono::DateTime<chrono::Utc> = log.get("started_at");
        let finished_at: Option<chrono::DateTime<chrono::Utc>> = log.get("finished_at");
        let status: String = log.get("status");
        let message: Option<String> = log.get("message");
        let records: i32 = log.get("records_processed");

        let duration = finished_at.map(|f| {
            let dur = f - started_at;
            format!("{}s", dur.num_seconds())
        }).unwrap_or_else(|| "-".to_string());

        let status_badge = match status.as_str() {
            "success" => r#"<span class="badge badge-success badge-sm">Success</span>"#,
            "error" => r#"<span class="badge badge-error badge-sm">Error</span>"#,
            _ => r#"<span class="badge badge-warning badge-sm">Running</span>"#,
        };

        logs_html.push_str(&format!(
            r#"<tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td class="text-xs">{}</td>
            </tr>"#,
            started_at.format("%Y-%m-%d %H:%M:%S"),
            duration,
            status_badge,
            records,
            message.unwrap_or_default()
        ));
    }

    if logs_html.is_empty() {
        logs_html = r#"<tr><td colspan="5" class="text-center text-base-content/50">No execution logs yet</td></tr>"#.to_string();
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Scheduled Job</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
    <script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-4xl">
        <div class="mb-6">
            <a href="/settings/cron" class="btn btn-ghost btn-sm">← Back to Scheduled Jobs</a>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="card bg-base-100 shadow">
                <div class="card-body">
                    <h2 class="card-title">{}</h2>
                    <p class="text-base-content/60 mb-4">Edit job settings</p>

                    <form method="post" action="/settings/cron/{}">
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Name</span></label>
                            <input type="text" name="name" class="input input-bordered" value="{}" required/>
                        </div>
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Function</span></label>
                            <input type="text" name="function_name" class="input input-bordered" value="{}" required/>
                        </div>
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div class="form-control mb-3">
                                <label class="label"><span class="label-text">Every</span></label>
                                <input type="number" name="interval_number" class="input input-bordered" value="{}" min="1"/>
                            </div>
                            <div class="form-control mb-3">
                                <label class="label"><span class="label-text">Period</span></label>
                                <select name="interval_type" class="select select-bordered">{}</select>
                            </div>
                        </div>
                        <div class="form-control mb-4">
                            <label class="label"><span class="label-text">Priority</span></label>
                            <input type="number" name="priority" class="input input-bordered" value="{}" min="1"/>
                            <label class="label"><span class="label-text-alt">Lower number = higher priority</span></label>
                        </div>
                        <div class="card-actions justify-between">
                            <form method="post" action="/settings/cron/{}/run" class="inline">
                                <button type="submit" class="btn btn-outline">Run Now</button>
                            </form>
                            <button type="submit" class="btn btn-primary">Save Changes</button>
                        </div>
                    </form>
                </div>
            </div>

            <div class="card bg-base-100 shadow">
                <div class="card-body">
                    <h2 class="card-title">Execution Log</h2>
                    <div class="overflow-x-auto">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>Started</th>
                                    <th>Duration</th>
                                    <th>Status</th>
                                    <th>Records</th>
                                    <th>Message</th>
                                </tr>
                            </thead>
                            <tbody>{}</tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>"##,
        name, user.username, name, id, name, function_name, interval_number, interval_select, priority, id, logs_html
    );

    Html(html).into_response()
}

async fn cron_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<CronForm>,
) -> Response {
    let interval_number = form.interval_number.unwrap_or(1);
    let interval_type = form.interval_type.as_deref().unwrap_or("days");

    // Recalculate next run time
    let next_run = match interval_type {
        "minutes" => chrono::Utc::now() + chrono::Duration::minutes(interval_number as i64),
        "hours" => chrono::Utc::now() + chrono::Duration::hours(interval_number as i64),
        "days" => chrono::Utc::now() + chrono::Duration::days(interval_number as i64),
        "weeks" => chrono::Utc::now() + chrono::Duration::weeks(interval_number as i64),
        "months" => chrono::Utc::now() + chrono::Duration::days(interval_number as i64 * 30),
        _ => chrono::Utc::now() + chrono::Duration::days(1),
    };

    let _ = sqlx::query(
        "UPDATE ir_cron SET name = $1, function_name = $2, interval_number = $3, interval_type = $4, next_run_at = $5, priority = $6, updated_at = NOW()
         WHERE id = $7"
    )
    .bind(&form.name)
    .bind(&form.function_name)
    .bind(interval_number)
    .bind(interval_type)
    .bind(next_run)
    .bind(form.priority.unwrap_or(10))
    .bind(id)
    .execute(&db)
    .await;

    Redirect::to("/settings/cron").into_response()
}

async fn cron_toggle(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let _ = sqlx::query("UPDATE ir_cron SET active = NOT active, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await;

    Redirect::to("/settings/cron").into_response()
}

async fn cron_run_now(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Get cron job info
    let cron = sqlx::query("SELECT function_name FROM ir_cron WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(cron) = cron else {
        return Redirect::to("/settings/cron").into_response();
    };

    let function_name: String = cron.get("function_name");

    // Create log entry
    let log_id = uuid::Uuid::now_v7();
    let _ = sqlx::query("INSERT INTO ir_cron_log (id, cron_id, status) VALUES ($1, $2, 'running')")
        .bind(log_id)
        .bind(id)
        .execute(&db)
        .await;

    // Execute the function (simplified - in production this would call actual functions)
    let (status, message, records) = match function_name.as_str() {
        "cleanup_expired_sessions" => {
            let result = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW() OR revoked = true")
                .execute(&db)
                .await;
            match result {
                Ok(r) => ("success", format!("Cleaned up {} sessions", r.rows_affected()), r.rows_affected() as i32),
                Err(e) => ("error", e.to_string(), 0),
            }
        },
        "check_overdue_activities" => {
            let result = sqlx::query(
                "UPDATE chatter_activities SET state = 'overdue' WHERE due_date < CURRENT_DATE AND state = 'pending'"
            )
            .execute(&db)
            .await;
            match result {
                Ok(r) => ("success", format!("Marked {} activities as overdue", r.rows_affected()), r.rows_affected() as i32),
                Err(e) => ("error", e.to_string(), 0),
            }
        },
        _ => ("success", "Function executed (no-op)".to_string(), 0),
    };

    // Update log entry
    let _ = sqlx::query(
        "UPDATE ir_cron_log SET finished_at = NOW(), status = $1, message = $2, records_processed = $3 WHERE id = $4"
    )
    .bind(status)
    .bind(&message)
    .bind(records)
    .bind(log_id)
    .execute(&db)
    .await;

    // Update cron job last run info
    let _ = sqlx::query(
        "UPDATE ir_cron SET last_run_at = NOW(), last_run_status = $1, last_run_message = $2 WHERE id = $3"
    )
    .bind(status)
    .bind(&message)
    .bind(id)
    .execute(&db)
    .await;

    Redirect::to(&format!("/settings/cron/{}", id)).into_response()
}

// ============================================================================
// Reports
// ============================================================================

async fn report_single(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path((model_name, record_id)): Path<(String, uuid::Uuid)>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Get report template
    let report_id = params.get("report_id");

    let report = if let Some(rid) = report_id {
        sqlx::query("SELECT id, name, template, paper_size, orientation FROM ir_report WHERE id = $1::uuid AND active = true")
            .bind(rid)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten()
    } else {
        sqlx::query("SELECT id, name, template, paper_size, orientation FROM ir_report WHERE model_name = $1 AND active = true ORDER BY sequence LIMIT 1")
            .bind(&model_name)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten()
    };

    let Some(report) = report else {
        return (StatusCode::NOT_FOUND, Html("No report template found for this model")).into_response();
    };

    let report_name: String = report.get("name");
    let template: String = report.get("template");
    let paper_size: String = report.get("paper_size");
    let orientation: String = report.get("orientation");

    // Get table name for model
    let table_name: Option<String> = sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(table_name) = table_name else {
        return (StatusCode::NOT_FOUND, Html("Model not found")).into_response();
    };

    // Fetch record data
    if !validate_identifier(&table_name) {
        return (StatusCode::BAD_REQUEST, Html("Invalid model")).into_response();
    }
    let query = format!("SELECT * FROM {} WHERE id = $1", table_name);
    let record = sqlx::query(&query)
        .bind(record_id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(record) = record else {
        return (StatusCode::NOT_FOUND, Html("Record not found")).into_response();
    };

    // Replace template placeholders with record data
    let mut html = template.clone();

    // Get column names and values
    for column in record.columns() {
        let col_name = column.name();
        let placeholder = format!("{{{{{}}}}}", col_name);

        let value: String = record.try_get::<String, _>(col_name)
            .or_else(|_| record.try_get::<Option<String>, _>(col_name).map(|v| v.unwrap_or_default()))
            .or_else(|_| record.try_get::<i32, _>(col_name).map(|v| v.to_string()))
            .or_else(|_| record.try_get::<i64, _>(col_name).map(|v| v.to_string()))
            .or_else(|_| record.try_get::<bool, _>(col_name).map(|v| v.to_string()))
            .or_else(|_| record.try_get::<uuid::Uuid, _>(col_name).map(|v| v.to_string()))
            .unwrap_or_default();

        html = html.replace(&placeholder, &html_escape(&value));
    }

    // Add generated timestamp
    html = html.replace("{{generated_at}}", &chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string());

    // Wrap in printable HTML
    let page_style = if orientation == "landscape" {
        "@page { size: landscape; }"
    } else {
        "@page { size: portrait; }"
    };

    let full_html = format!(
        r##"<!DOCTYPE html>
<html>
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <title>{} - {}</title>
    <script src="/static/vendor/tailwind.js"></script>
    <style>
        {}
        @media print {{
            body {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
            .no-print {{ display: none !important; }}
        }}
    </style>
</head>
<body class="bg-white">
    <div class="no-print fixed top-4 right-4 flex gap-2">
        <button onclick="window.print()" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
            Print / Save PDF
        </button>
        <button onclick="window.close()" class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">
            Close
        </button>
    </div>
    {}
</body>
</html>"##,
        report_name, model_name, page_style, html
    );

    Html(full_html).into_response()
}

async fn report_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(model_name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Get report template for list view
    let report = sqlx::query(
        "SELECT id, name, template, paper_size, orientation FROM ir_report WHERE model_name = $1 AND name LIKE '%List%' AND active = true ORDER BY sequence LIMIT 1"
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(report) = report else {
        return (StatusCode::NOT_FOUND, Html("No list report template found for this model")).into_response();
    };

    let report_name: String = report.get("name");
    let template: String = report.get("template");

    // Get table name
    let table_name: Option<String> = sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(table_name) = table_name else {
        return (StatusCode::NOT_FOUND, Html("Model not found")).into_response();
    };

    // Fetch records
    if !validate_identifier(&table_name) {
        return (StatusCode::BAD_REQUEST, Html("Invalid model")).into_response();
    }
    let limit = params.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100);
    let query = format!("SELECT * FROM {} WHERE active = true LIMIT {}", table_name, limit);
    let records = sqlx::query(&query)
        .fetch_all(&db)
        .await
        .unwrap_or_default();

    // Build records HTML from template
    let mut html = template.clone();

    // Find the {{#records}}...{{/records}} section
    if let (Some(start), Some(end)) = (html.find("{{#records}}"), html.find("{{/records}}")) {
        let row_template = &html[start + 12..end];
        let mut rows_html = String::new();

        for record in &records {
            let mut row = row_template.to_string();
            for column in record.columns() {
                let col_name = column.name();
                let placeholder = format!("{{{{{}}}}}", col_name);

                let value: String = record.try_get::<String, _>(col_name)
                    .or_else(|_| record.try_get::<Option<String>, _>(col_name).map(|v| v.unwrap_or_default()))
                    .or_else(|_| record.try_get::<i32, _>(col_name).map(|v| v.to_string()))
                    .or_else(|_| record.try_get::<bool, _>(col_name).map(|v| v.to_string()))
                    .unwrap_or_default();

                row = row.replace(&placeholder, &html_escape(&value));
            }
            rows_html.push_str(&row);
        }

        html = format!("{}{}{}", &html[..start], rows_html, &html[end + 12..]);
    }

    html = html.replace("{{generated_at}}", &chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string());
    html = html.replace("{{record_count}}", &records.len().to_string());

    let full_html = format!(
        r##"<!DOCTYPE html>
<html>
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <title>{}</title>
    <script src="/static/vendor/tailwind.js"></script>
    <style>
        @media print {{
            body {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
            .no-print {{ display: none !important; }}
        }}
    </style>
</head>
<body class="bg-white">
    <div class="no-print fixed top-4 right-4 flex gap-2">
        <button onclick="window.print()" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
            Print / Save PDF
        </button>
        <button onclick="window.close()" class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">
            Close
        </button>
    </div>
    {}
</body>
</html>"##,
        report_name, html
    );

    Html(full_html).into_response()
}

// ── User-authored report builder + runner (vortex_framework::user_reports) ──

/// May this user create/edit reports? Admins, or holders of "Report Author".
fn report_author(user: &AuthUser) -> bool {
    user.is_admin() || user.roles.iter().any(|r| r == "Report Author")
}

/// `<option>`s of a model's visible fields (from the model registry).
async fn report_field_options(db: &sqlx::PgPool, model_name: &str, selected: &str, blank: Option<&str>) -> String {
    let rows = sqlx::query(
        "SELECT f.name, f.display_name, f.field_type FROM ir_model_field f \
         JOIN ir_model m ON m.id = f.model_id WHERE m.name = $1 ORDER BY f.sequence, f.name",
    )
    .bind(model_name)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::new();
    if let Some(b) = blank {
        let sel = if selected.is_empty() { " selected" } else { "" };
        out.push_str(&format!(r#"<option value=""{sel}>{}</option>"#, html_escape(b)));
    }
    for r in &rows {
        let name: String = r.get("name");
        let disp: Option<String> = r.try_get("display_name").ok().flatten();
        let ftype: String = r.get("field_type");
        let sel = if name == selected { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{name}"{sel}>{label} ({ftype})</option>"#,
            name = html_escape(&name),
            sel = sel,
            label = html_escape(disp.as_deref().unwrap_or(&name)),
            ftype = html_escape(&ftype),
        ));
    }
    out
}

#[derive(Debug, serde::Deserialize)]
struct ReportCreateForm {
    code: String,
    name: String,
    model_name: String,
    report_type: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ReportBasicsForm {
    name: String,
    description: Option<String>,
    report_type: Option<String>,
    sort_field: Option<String>,
    sort_dir: Option<String>,
    group_field: Option<String>,
    row_limit: Option<i32>,
    paper_size: Option<String>,
    orientation: Option<String>,
    required_role: Option<String>,
    template: Option<String>,
    active: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ColumnAddForm {
    field: String,
    label: Option<String>,
    aggregate: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct FilterAddForm {
    field: String,
    operator: Option<String>,
    value: Option<String>,
}

async fn reports_list(Db(db): Db, Extension(user): Extension<AuthUser>) -> Response {
    if !report_author(&user) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Reports"))).into_response();
    }
    let reports = sqlx::query(
        "SELECT id, code, name, model_name, report_type, active FROM ir_report ORDER BY model_name, sequence, name",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows_html = String::new();
    for report in &reports {
        let id: uuid::Uuid = report.get("id");
        let code: String = report.get("code");
        let name: String = report.get("name");
        let model_name: String = report.get("model_name");
        let report_type: String = report.get("report_type");
        let active: bool = report.get("active");
        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/reports/{id}" class="link link-primary">{name}</a><div class="text-xs opacity-50">{code}</div></td>
                <td><code class="text-xs">{model}</code></td>
                <td><span class="badge badge-ghost badge-sm">{rtype}</span></td>
                <td>{status}</td>
                <td class="text-right"><a href="/reports/run/{id}" class="btn btn-xs btn-outline" target="_blank">Run</a></td>
            </tr>"##,
            id = id,
            name = html_escape(&name),
            code = html_escape(&code),
            model = html_escape(&model_name),
            rtype = html_escape(&report_type),
            status = if active { r#"<span class="badge badge-success badge-sm">Active</span>"# } else { r#"<span class="badge badge-ghost badge-sm">Inactive</span>"# },
        ));
    }
    if reports.is_empty() {
        rows_html.push_str(r#"<tr><td colspan="5" class="text-center opacity-50 py-8">No reports yet — create one to get started.</td></tr>"#);
    }

    let models: Vec<String> = sqlx::query_scalar("SELECT name FROM ir_model WHERE is_active = true ORDER BY name")
        .fetch_all(&db)
        .await
        .unwrap_or_default();
    let model_opts: String = models.iter().map(|m| format!(r#"<option value="{0}">{0}</option>"#, html_escape(m))).collect();

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports - Settings</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg"><div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div><div class="flex-none"><span class="text-sm">@{user}</span></div></div>
    <div class="container mx-auto p-6 max-w-4xl">
        <div class="flex justify-between items-center mb-6">
            <div><h1 class="text-2xl font-bold">Reports</h1>
            <p class="text-base-content/60">Build your own reports — pick a model and columns (tabular) or author an HTML template. No code required.</p></div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Report</button>
        </div>
        <div class="card bg-base-100 shadow"><div class="card-body p-0 overflow-x-auto">
            <table class="table"><thead><tr><th>Name</th><th>Model</th><th>Type</th><th>Status</th><th></th></tr></thead><tbody>{rows}</tbody></table>
        </div></div>
        <div class="mt-4"><a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a></div>
    </div>
    <dialog id="create-modal" class="modal"><div class="modal-box">
        <h3 class="font-bold text-lg mb-4">New Report</h3>
        <form method="post" action="/settings/reports">
            <div class="grid grid-cols-2 gap-4">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Code</span></label>
                    <input name="code" class="input input-bordered" placeholder="contacts_by_country" required/></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Name</span></label>
                    <input name="name" class="input input-bordered" placeholder="Contacts by Country" required/></div>
            </div>
            <div class="grid grid-cols-2 gap-4">
                <div class="form-control mb-3"><label class="label"><span class="label-text">Model</span></label>
                    <select name="model_name" class="select select-bordered" required>{model_opts}</select></div>
                <div class="form-control mb-3"><label class="label"><span class="label-text">Type</span></label>
                    <select name="report_type" class="select select-bordered">
                        <option value="tabular">Tabular (columns + groups)</option>
                        <option value="template">Template (HTML document)</option>
                    </select></div>
            </div>
            <div class="modal-action">
                <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                <button type="submit" class="btn btn-primary">Create &amp; configure</button>
            </div>
        </form>
    </div><form method="dialog" class="modal-backdrop"><button>close</button></form></dialog>
</body></html>"##,
        user = html_escape(&user.username),
        rows = rows_html,
        model_opts = model_opts,
    );
    Html(html).into_response()
}

async fn report_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<ReportCreateForm>,
) -> Response {
    if !report_author(&user) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Reports"))).into_response();
    }
    let code = form.code.trim().to_lowercase();
    let name = form.name.trim().to_string();
    let model = form.model_name.trim().to_string();
    if code.is_empty() || name.is_empty() || model.is_empty() {
        return settings_write_error("/settings/reports", "Code, name and model are required.");
    }
    let rtype = match form.report_type.as_deref() { Some("template") => "template", _ => "tabular" };
    let row = sqlx::query(
        "INSERT INTO ir_report (code, name, model_name, report_type, created_by) \
         VALUES ($1,$2,$3,$4,$5) RETURNING id",
    )
    .bind(&code).bind(&name).bind(&model).bind(rtype).bind(user.id)
    .fetch_optional(&db)
    .await;
    let new_id = match row {
        Ok(Some(r)) => r.get::<uuid::Uuid, _>("id"),
        _ => return settings_write_error("/settings/reports", "Could not create report (code may already exist)."),
    };
    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id)).with_username(&user.username)
        .with_database(&db_ctx.db_name).with_resource("ir_report", &code).with_resource_name(&name)
        .with_details(serde_json::json!({"action":"create","model":model,"type":rtype}));
    let _ = state.audit.log(entry).await;
    Redirect::to(&format!("/settings/reports/{new_id}")).into_response()
}

async fn report_edit(Db(db): Db, Extension(user): Extension<AuthUser>, Path(id): Path<uuid::Uuid>) -> Response {
    if !report_author(&user) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Reports"))).into_response();
    }
    let Some(def) = vortex_framework::user_reports::load(&db, id).await else {
        return Redirect::to("/settings/reports").into_response();
    };
    let is_template = def.report_type == "template";

    // Columns table + filters table.
    let cols = sqlx::query("SELECT id, field, label, aggregate FROM ir_report_column WHERE report_id = $1 ORDER BY sequence, field")
        .bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut cols_html = String::new();
    for c in &cols {
        let cid: uuid::Uuid = c.get("id");
        let field: String = c.get("field");
        let label: Option<String> = c.try_get("label").ok().flatten();
        let agg: String = c.get("aggregate");
        cols_html.push_str(&format!(
            r##"<tr><td><code class="text-xs">{field}</code></td><td>{label}</td><td>{agg}</td>
            <td class="text-right"><form method="post" action="/settings/reports/{id}/columns/{cid}/delete" class="inline"><button class="btn btn-xs btn-error btn-outline">×</button></form></td></tr>"##,
            field = html_escape(&field), label = html_escape(label.as_deref().unwrap_or("")),
            agg = if agg == "none" { String::new() } else { format!(r#"<span class="badge badge-sm">{}</span>"#, html_escape(&agg)) },
            id = id, cid = cid,
        ));
    }
    let filters = sqlx::query("SELECT id, field, operator, value FROM ir_report_filter WHERE report_id = $1 ORDER BY sequence")
        .bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut filt_html = String::new();
    for f in &filters {
        let fid: uuid::Uuid = f.get("id");
        let field: String = f.get("field");
        let op: String = f.get("operator");
        let val: Option<String> = f.try_get("value").ok().flatten();
        filt_html.push_str(&format!(
            r##"<tr><td><code class="text-xs">{field}</code></td><td>{op}</td><td>{val}</td>
            <td class="text-right"><form method="post" action="/settings/reports/{id}/filters/{fid}/delete" class="inline"><button class="btn btn-xs btn-error btn-outline">×</button></form></td></tr>"##,
            field = html_escape(&field), op = html_escape(&op), val = html_escape(val.as_deref().unwrap_or("")), id = id, fid = fid,
        ));
    }

    let field_opts_col = report_field_options(&db, &def.model_name, "", None).await;
    let field_opts_filter = report_field_options(&db, &def.model_name, "", None).await;
    let group_opts = report_field_options(&db, &def.model_name, def.group_field.as_deref().unwrap_or(""), Some("— No grouping —")).await;
    let sort_opts = report_field_options(&db, &def.model_name, def.sort_field.as_deref().unwrap_or(""), Some("— Default —")).await;
    let roles: Vec<String> = sqlx::query_scalar("SELECT name FROM roles ORDER BY name").fetch_all(&db).await.unwrap_or_default();
    let role_opts: String = {
        let mut o = format!(r#"<option value=""{}>— Any user —</option>"#, if def.required_role.is_none() { " selected" } else { "" });
        for r in &roles {
            let sel = if def.required_role.as_deref() == Some(r) { " selected" } else { "" };
            o.push_str(&format!(r#"<option value="{0}"{1}>{0}</option>"#, html_escape(r), sel));
        }
        o
    };
    let agg_opts = |sel: &str| -> String {
        ["none","sum","avg","count","min","max"].iter().map(|a| {
            format!(r#"<option value="{a}"{s}>{a}</option>"#, a = a, s = if *a == sel { " selected" } else { "" })
        }).collect()
    };
    let op_opts: String = ["=","!=","ilike",">","<",">=","<="].iter().map(|o| format!(r#"<option value="{0}">{0}</option>"#, o)).collect();

    // Field reference for template authors.
    let field_ref = report_field_options(&db, &def.model_name, "", None).await
        .replace("<option", "<li class=\"text-xs\"><code")
        .replace("</option>", "</code></li>");

    let tabular_section = format!(
        r##"<div class="card bg-base-100 shadow mb-4"><div class="card-body">
        <h2 class="card-title text-base">Columns</h2>
        <table class="table table-sm"><thead><tr><th>Field</th><th>Label</th><th>Aggregate</th><th></th></tr></thead><tbody>{cols}</tbody></table>
        <form method="post" action="/settings/reports/{id}/columns" class="flex flex-wrap gap-2 items-end mt-2">
            <div class="form-control"><label class="label py-0"><span class="label-text text-xs">Field</span></label><select name="field" class="select select-bordered select-sm" required>{field_opts_col}</select></div>
            <div class="form-control"><label class="label py-0"><span class="label-text text-xs">Label</span></label><input name="label" class="input input-bordered input-sm" placeholder="(optional)"/></div>
            <div class="form-control"><label class="label py-0"><span class="label-text text-xs">Aggregate</span></label><select name="aggregate" class="select select-bordered select-sm">{agg_none}</select></div>
            <button class="btn btn-sm btn-primary">Add column</button>
        </form></div></div>

        <div class="card bg-base-100 shadow mb-4"><div class="card-body">
        <h2 class="card-title text-base">Filters <span class="text-xs opacity-50">(all conditions must match)</span></h2>
        <table class="table table-sm"><thead><tr><th>Field</th><th>Op</th><th>Value</th><th></th></tr></thead><tbody>{filt}</tbody></table>
        <form method="post" action="/settings/reports/{id}/filters" class="flex flex-wrap gap-2 items-end mt-2">
            <div class="form-control"><label class="label py-0"><span class="label-text text-xs">Field</span></label><select name="field" class="select select-bordered select-sm" required>{field_opts_filter}</select></div>
            <div class="form-control"><label class="label py-0"><span class="label-text text-xs">Operator</span></label><select name="operator" class="select select-bordered select-sm">{op_opts}</select></div>
            <div class="form-control"><label class="label py-0"><span class="label-text text-xs">Value</span></label><input name="value" class="input input-bordered input-sm"/></div>
            <button class="btn btn-sm btn-primary">Add filter</button>
        </form></div></div>"##,
        cols = cols_html, id = id, field_opts_col = field_opts_col, agg_none = agg_opts("none"),
        filt = filt_html, field_opts_filter = field_opts_filter, op_opts = op_opts,
    );

    let template_section = format!(
        r##"<div class="card bg-base-100 shadow mb-4"><div class="card-body">
        <h2 class="card-title text-base">Template (HTML)</h2>
        <p class="text-xs opacity-60">Syntax: <code>{{{{ field }}}}</code>, <code>{{%for r in records%}}…{{%endfor%}}</code>, <code>{{%if field%}}…{{%endif%}}</code>. Data is auto-escaped. Globals: <code>report_name</code>, <code>generated_at</code>, <code>count</code>.</p>
        <textarea name="template" form="basics-form" class="textarea textarea-bordered font-mono text-xs h-64 w-full">{template}</textarea>
        <details class="mt-2"><summary class="text-xs cursor-pointer">Available fields for <code>{model}</code></summary><ul class="mt-1 ml-4 list-disc">{field_ref}</ul></details>
        </div></div>"##,
        template = html_escape(def.template.as_deref().unwrap_or("")), model = html_escape(&def.model_name), field_ref = field_ref,
    );

    let body_section = if is_template { template_section } else { tabular_section };

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{name} - Report</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg"><div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div><div class="flex-none"><span class="text-sm">@{user}</span></div></div>
    <div class="container mx-auto p-6 max-w-3xl">
        <div class="flex justify-between items-center mb-4">
            <a href="/settings/reports" class="btn btn-ghost btn-sm">← Reports</a>
            <a href="/reports/run/{id}" target="_blank" class="btn btn-sm btn-success">▶ Run report</a>
        </div>
        <div class="card bg-base-100 shadow mb-4"><div class="card-body">
            <h2 class="card-title">{name} <span class="badge badge-ghost">{rtype}</span> <code class="text-xs opacity-50">{model}</code></h2>
            <form id="basics-form" method="post" action="/settings/reports/{id}">
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-2"><label class="label"><span class="label-text">Name</span></label><input name="name" class="input input-bordered input-sm" value="{name}" required/></div>
                    <div class="form-control mb-2"><label class="label"><span class="label-text">Can run (role)</span></label><select name="required_role" class="select select-bordered select-sm">{role_opts}</select></div>
                </div>
                <div class="form-control mb-2"><label class="label"><span class="label-text">Description</span></label><input name="description" class="input input-bordered input-sm" value="{description}"/></div>
                <div class="grid grid-cols-4 gap-3">
                    <div class="form-control mb-2"><label class="label"><span class="label-text text-xs">Group by</span></label><select name="group_field" class="select select-bordered select-sm">{group_opts}</select></div>
                    <div class="form-control mb-2"><label class="label"><span class="label-text text-xs">Sort by</span></label><select name="sort_field" class="select select-bordered select-sm">{sort_opts}</select></div>
                    <div class="form-control mb-2"><label class="label"><span class="label-text text-xs">Direction</span></label><select name="sort_dir" class="select select-bordered select-sm"><option value="asc"{asc}>Asc</option><option value="desc"{desc}>Desc</option></select></div>
                    <div class="form-control mb-2"><label class="label"><span class="label-text text-xs">Row limit</span></label><input name="row_limit" type="number" class="input input-bordered input-sm" value="{row_limit}"/></div>
                </div>
                <input type="hidden" name="report_type" value="{rtype}"/>
                <div class="grid grid-cols-2 gap-3 {tmpl_show}">
                    <div class="form-control mb-2"><label class="label"><span class="label-text text-xs">Paper</span></label><select name="paper_size" class="select select-bordered select-sm"><option {a4}>A4</option><option {lt}>Letter</option><option {lg}>Legal</option></select></div>
                    <div class="form-control mb-2"><label class="label"><span class="label-text text-xs">Orientation</span></label><select name="orientation" class="select select-bordered select-sm"><option value="portrait"{port}>Portrait</option><option value="landscape"{land}>Landscape</option></select></div>
                </div>
                <label class="cursor-pointer label justify-start gap-3 mt-1"><input type="checkbox" name="active" class="checkbox checkbox-sm" {active}/><span class="label-text">Active</span></label>
                <div class="flex justify-between mt-3">
                    <form method="post" action="/settings/reports/{id}/delete" class="inline"><button class="btn btn-sm btn-error btn-outline" onclick="return confirm('Delete this report?');">Delete</button></form>
                    <button type="submit" class="btn btn-sm btn-primary">Save</button>
                </div>
            </form>
        </div></div>
        {body_section}
    </div>
</body></html>"##,
        user = html_escape(&user.username), id = id, name = html_escape(&def.name), rtype = html_escape(&def.report_type),
        model = html_escape(&def.model_name), role_opts = role_opts,
        description = html_escape(def.description.as_deref().unwrap_or("")),
        group_opts = group_opts, sort_opts = sort_opts,
        asc = if def.sort_dir != "desc" { "selected" } else { "" }, desc = if def.sort_dir == "desc" { "selected" } else { "" },
        row_limit = def.row_limit,
        tmpl_show = if is_template { "" } else { "hidden" },
        a4 = if def.paper_size == "A4" { "selected" } else { "" }, lt = if def.paper_size == "Letter" { "selected" } else { "" }, lg = if def.paper_size == "Legal" { "selected" } else { "" },
        port = if def.orientation != "landscape" { "selected" } else { "" }, land = if def.orientation == "landscape" { "selected" } else { "" },
        active = "checked",
        body_section = body_section,
    );
    Html(html).into_response()
}

async fn report_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<ReportBasicsForm>,
) -> Response {
    if !report_author(&user) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Reports"))).into_response();
    }
    let name = form.name.trim().to_string();
    if name.is_empty() {
        return settings_write_error(&format!("/settings/reports/{id}"), "Name is required.");
    }
    let rtype = match form.report_type.as_deref() { Some("template") => "template", _ => "tabular" };
    let sort_dir = if form.sort_dir.as_deref() == Some("desc") { "desc" } else { "asc" };
    let blank_to_null = |o: Option<String>| o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let _ = sqlx::query(
        "UPDATE ir_report SET name=$1, description=$2, report_type=$3, sort_field=$4, sort_dir=$5, \
         group_field=$6, row_limit=$7, paper_size=$8, orientation=$9, required_role=$10, template=$11, \
         active=$12, updated_at=NOW() WHERE id=$13",
    )
    .bind(&name)
    .bind(blank_to_null(form.description))
    .bind(rtype)
    .bind(blank_to_null(form.sort_field))
    .bind(sort_dir)
    .bind(blank_to_null(form.group_field))
    .bind(form.row_limit.unwrap_or(1000).clamp(1, 100_000))
    .bind(form.paper_size.as_deref().unwrap_or("A4"))
    .bind(form.orientation.as_deref().unwrap_or("portrait"))
    .bind(blank_to_null(form.required_role))
    .bind(blank_to_null(form.template))
    .bind(form.active.is_some())
    .bind(id)
    .execute(&db)
    .await;
    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id)).with_username(&user.username)
        .with_database(&db_ctx.db_name).with_resource("ir_report", id.to_string()).with_resource_name(&name)
        .with_details(serde_json::json!({"action":"update"}));
    let _ = state.audit.log(entry).await;
    Redirect::to(&format!("/settings/reports/{id}")).into_response()
}

async fn report_column_add(
    Db(db): Db, Extension(user): Extension<AuthUser>, Path(id): Path<uuid::Uuid>, Form(form): Form<ColumnAddForm>,
) -> Response {
    if !report_author(&user) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Reports"))).into_response();
    }
    let field = form.field.trim().to_string();
    if validate_identifier(&field) {
        let agg = form.aggregate.as_deref().filter(|a| ["none","sum","avg","count","min","max"].contains(a)).unwrap_or("none");
        let label = form.label.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let seq: i32 = sqlx::query_scalar("SELECT COALESCE(MAX(sequence),0)+10 FROM ir_report_column WHERE report_id=$1")
            .bind(id).fetch_one(&db).await.unwrap_or(10);
        let _ = sqlx::query("INSERT INTO ir_report_column (report_id, field, label, aggregate, sequence) VALUES ($1,$2,$3,$4,$5)")
            .bind(id).bind(&field).bind(label).bind(agg).bind(seq).execute(&db).await;
    }
    Redirect::to(&format!("/settings/reports/{id}")).into_response()
}

async fn report_column_delete(Db(db): Db, Extension(user): Extension<AuthUser>, Path((id, cid)): Path<(uuid::Uuid, uuid::Uuid)>) -> Response {
    if !report_author(&user) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Reports"))).into_response();
    }
    let _ = sqlx::query("DELETE FROM ir_report_column WHERE id=$1 AND report_id=$2").bind(cid).bind(id).execute(&db).await;
    Redirect::to(&format!("/settings/reports/{id}")).into_response()
}

async fn report_filter_add(
    Db(db): Db, Extension(user): Extension<AuthUser>, Path(id): Path<uuid::Uuid>, Form(form): Form<FilterAddForm>,
) -> Response {
    if !report_author(&user) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Reports"))).into_response();
    }
    let field = form.field.trim().to_string();
    let op = form.operator.as_deref().filter(|o| ["=","!=","ilike",">","<",">=","<="].contains(o)).unwrap_or("=");
    if validate_identifier(&field) {
        let seq: i32 = sqlx::query_scalar("SELECT COALESCE(MAX(sequence),0)+10 FROM ir_report_filter WHERE report_id=$1")
            .bind(id).fetch_one(&db).await.unwrap_or(10);
        let _ = sqlx::query("INSERT INTO ir_report_filter (report_id, field, operator, value, sequence) VALUES ($1,$2,$3,$4,$5)")
            .bind(id).bind(&field).bind(op).bind(form.value.as_deref()).bind(seq).execute(&db).await;
    }
    Redirect::to(&format!("/settings/reports/{id}")).into_response()
}

async fn report_filter_delete(Db(db): Db, Extension(user): Extension<AuthUser>, Path((id, fid)): Path<(uuid::Uuid, uuid::Uuid)>) -> Response {
    if !report_author(&user) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Reports"))).into_response();
    }
    let _ = sqlx::query("DELETE FROM ir_report_filter WHERE id=$1 AND report_id=$2").bind(fid).bind(id).execute(&db).await;
    Redirect::to(&format!("/settings/reports/{id}")).into_response()
}

async fn report_delete(
    State(state): State<Arc<AppState>>, Db(db): Db, Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>, Path(id): Path<uuid::Uuid>,
) -> Response {
    if !report_author(&user) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Reports"))).into_response();
    }
    let _ = sqlx::query("DELETE FROM ir_report WHERE id=$1").bind(id).execute(&db).await;
    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id)).with_username(&user.username)
        .with_database(&db_ctx.db_name).with_resource("ir_report", id.to_string())
        .with_details(serde_json::json!({"action":"delete"}));
    let _ = state.audit.log(entry).await;
    Redirect::to("/settings/reports").into_response()
}

/// GET /reports — a hub listing reports the current user is allowed to run.
async fn reports_hub(
    State(state): State<Arc<AppState>>, Db(db): Db, Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let reports = sqlx::query("SELECT id, code, name, description, model_name, report_type, required_role FROM ir_report WHERE active = true ORDER BY name")
        .fetch_all(&db).await.unwrap_or_default();
    let mut cards = String::new();
    for r in &reports {
        let req: Option<String> = r.try_get("required_role").ok().flatten();
        let allowed = match &req { None => true, Some(role) => user.is_admin() || user.roles.iter().any(|x| x == role) };
        if !allowed { continue; }
        let id: uuid::Uuid = r.get("id");
        let name: String = r.get("name");
        let desc: Option<String> = r.try_get("description").ok().flatten();
        let model: String = r.get("model_name");
        let rtype: String = r.get("report_type");
        let csv_btn = if rtype == "tabular" {
            format!(r##"<form method="post" action="/reports/queue/{id}?format=csv" class="inline"><button class="btn btn-xs btn-ghost" title="Generate CSV in the background">⏱ CSV</button></form>"##)
        } else { String::new() };
        cards.push_str(&format!(
            r##"<div class="card bg-base-100 shadow hover:shadow-lg transition"><div class="card-body p-4">
            <h3 class="card-title text-base"><a href="/reports/run/{id}" target="_blank" class="link link-hover">{name}</a> <span class="badge badge-ghost badge-sm">{rtype}</span></h3>
            <p class="text-sm opacity-60">{desc}</p><p class="text-xs opacity-40"><code>{model}</code></p>
            <div class="card-actions items-center mt-1"><a href="/reports/run/{id}" target="_blank" class="btn btn-xs btn-outline">▶ Run</a>
            <form method="post" action="/reports/queue/{id}?format=pdf" class="inline"><button class="btn btn-xs btn-ghost" title="Generate PDF in the background">⏱ PDF</button></form>{csv_btn}</div>
            </div></div>"##,
            id = id, name = html_escape(&name), rtype = html_escape(&rtype),
            desc = html_escape(desc.as_deref().unwrap_or("")), model = html_escape(&model), csv_btn = csv_btn,
        ));
    }
    if cards.is_empty() {
        cards.push_str(r#"<div class="alert">No reports available to you yet.</div>"#);
    }
    let author_btn = if report_author(&user) { r#"<a href="/settings/reports" class="btn btn-sm btn-outline">Build reports</a>"# } else { "" };
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("reports", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    let content = format!(
        r##"<div class="flex justify-between items-center mb-6"><div><h1 class="text-2xl font-bold">Reports</h1><p class="text-base-content/60 text-sm">Run now, or queue in the background (⏱) and pick it up from Generated Reports</p></div>
        <div class="flex gap-2"><a href="/reports/runs" class="btn btn-sm btn-outline">🗂 Generated Reports</a>{author_btn}</div></div>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">{cards}</div>"##,
        author_btn = author_btn, cards = cards,
    );
    let html = format!(
        r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><title>Reports - Remicle</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0"><link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200"><div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}<main class="flex-1 p-4 lg:p-6 min-w-0">{content}</main></div></body></html>"#,
        sidebar = sidebar, content = content,
    );
    Html(html).into_response()
}

/// GET /reports/run/{id} — render a report. ?format=csv|json for downloads.
async fn report_run(
    State(state): State<Arc<AppState>>, Db(db): Db, Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>, Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    use vortex_framework::user_reports as ur;
    let Some(def) = ur::load(&db, id).await else {
        return (StatusCode::NOT_FOUND, Html("Report not found")).into_response();
    };
    if !def.can_run(&user.roles, user.is_admin()) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page(&def.name))).into_response();
    }
    let format = q.get("format").map(|s| s.as_str()).unwrap_or("html");

    // Audit the run (read/export) against the tenant DB.
    let entry = AuditEntry::new(AuditAction::BulkExport, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id)).with_username(&user.username)
        .with_database(&db_ctx.db_name).with_resource("ir_report", def.code.clone()).with_resource_name(&def.name)
        .with_details(serde_json::json!({"action":"run","format":format}));
    let _ = state.audit.log(entry).await;

    // Build the printable HTML page for both shapes. CSV/JSON short-circuit
    // (tabular only); HTML and PDF share the same rendered page.
    let printable: String = if def.report_type == "template" {
        let records = match ur::fetch_template_records(&db, &def).await {
            Ok(r) => r, Err(e) => return (StatusCode::BAD_REQUEST, Html(format!("Report error: {}", html_escape(&e)))).into_response(),
        };
        let mut globals = std::collections::BTreeMap::new();
        globals.insert("report_name".to_string(), def.name.clone());
        globals.insert("generated_at".to_string(), chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string());
        globals.insert("count".to_string(), records.len().to_string());
        let inner = ur::render_template(def.template.as_deref().unwrap_or(""), &records, &globals);
        report_print_page(&def, &inner)
    } else {
        let res = match ur::run_tabular(&db, &def).await {
            Ok(r) => r, Err(e) => return (StatusCode::BAD_REQUEST, Html(format!("Report error: {}", html_escape(&e)))).into_response(),
        };
        match format {
            "csv" => {
                let bytes = ur::render_tabular_csv(&res);
                return ([(axum::http::header::CONTENT_TYPE, "text/csv"),
                  (axum::http::header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}.csv\"", def.code))], bytes).into_response();
            }
            "json" => {
                return ([(axum::http::header::CONTENT_TYPE, "application/json")], ur::render_tabular_json(&res)).into_response();
            }
            _ => report_print_page(&def, &ur::render_tabular_html(&def, &res)),
        }
    };

    if format == "pdf" {
        use vortex_framework::pdf;
        let opts = pdf::PdfOptions {
            landscape: def.orientation == "landscape",
            paper: pdf::Paper::parse(&def.paper_size),
            print_background: true,
            margin_in: 0.4,
        };
        return match pdf::html_to_pdf(&printable, &opts).await {
            Ok(bytes) => ([(axum::http::header::CONTENT_TYPE, "application/pdf"),
                (axum::http::header::CONTENT_DISPOSITION, &format!("inline; filename=\"{}.pdf\"", def.code))], bytes).into_response(),
            Err(pdf::PdfError::NotAvailable) => (
                StatusCode::NOT_IMPLEMENTED,
                Html("PDF export is not enabled in this build. Rebuild the server with <code>--features pdf</code> and install a Chromium binary."),
            ).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("PDF render failed: {}", html_escape(&e.to_string())))).into_response(),
        };
    }

    Html(printable).into_response()
}

/// POST /reports/queue/{id}?format=pdf|html|csv — run a report in the
/// background: enqueue a `report.render` job, then send the user to
/// the Generated Reports inbox. Heavy reports (multi-year GL) go this
/// way instead of holding an HTTP request open.
async fn report_queue(
    State(state): State<Arc<AppState>>, Db(db): Db, Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>, Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    use vortex_framework::user_reports as ur;
    let Some(def) = ur::load(&db, id).await else {
        return (StatusCode::NOT_FOUND, Html("Report not found")).into_response();
    };
    if !def.can_run(&user.roles, user.is_admin()) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page(&def.name))).into_response();
    }
    let format = q.get("format").map(|s| s.as_str()).unwrap_or("pdf");

    let entry = AuditEntry::new(AuditAction::BulkExport, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id)).with_username(&user.username)
        .with_database(&db_ctx.db_name).with_resource("ir_report", def.code.clone()).with_resource_name(&def.name)
        .with_details(serde_json::json!({"action":"queue","format":format}));
    let _ = state.audit.log(entry).await;

    match vortex_framework::report_jobs::enqueue_run(
        &state.db, &db, &db_ctx.db_name, &def, format, user.id, &user.username,
    ).await {
        Ok(_) => Redirect::to("/reports/runs").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Html(format!("Could not queue report: {}", html_escape(&e)))).into_response(),
    }
}

/// GET /reports/runs — the Generated Reports inbox: every background
/// run you requested (admins see the whole tenant), with status,
/// download links for finished artifacts, and retry for failures.
async fn report_runs_page(
    State(state): State<Arc<AppState>>, Db(db): Db, Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let rows = if user.is_admin() {
        sqlx::query(
            "SELECT id, report_name, format, status, error, file_size, requested_by_name, created_at, started_at, finished_at \
             FROM report_runs ORDER BY created_at DESC LIMIT 200",
        ).fetch_all(&db).await
    } else {
        sqlx::query(
            "SELECT id, report_name, format, status, error, file_size, requested_by_name, created_at, started_at, finished_at \
             FROM report_runs WHERE requested_by = $1 ORDER BY created_at DESC LIMIT 200",
        ).bind(user.id).fetch_all(&db).await
    }.unwrap_or_default();

    let mut trs = String::new();
    let mut any_active = false;
    for r in &rows {
        let id: uuid::Uuid = r.get("id");
        let name: String = r.get("report_name");
        let format: String = r.get("format");
        let status: String = r.get("status");
        let error: Option<String> = r.try_get("error").ok().flatten();
        let size: Option<i64> = r.try_get("file_size").ok().flatten();
        let who: Option<String> = r.try_get("requested_by_name").ok().flatten();
        let created: chrono::DateTime<chrono::Utc> = r.get("created_at");
        let started: Option<chrono::DateTime<chrono::Utc>> = r.try_get("started_at").ok().flatten();
        let finished: Option<chrono::DateTime<chrono::Utc>> = r.try_get("finished_at").ok().flatten();

        let (badge, result) = match status.as_str() {
            "done" => {
                let dur = match (started, finished) {
                    (Some(s), Some(f)) => format!(" in {}s", (f - s).num_seconds().max(0)),
                    _ => String::new(),
                };
                let size_h = size.map(human_size).unwrap_or_default();
                (
                    format!(r#"<span class="badge badge-success badge-sm">done{dur}</span>"#),
                    format!(r#"<a class="btn btn-xs btn-primary" href="/reports/runs/{id}/download">⬇ Download {fmt} {size_h}</a>"#,
                        id = id, fmt = html_escape(&format.to_uppercase()), size_h = size_h),
                )
            }
            "failed" => (
                format!(r#"<span class="badge badge-error badge-sm" title="{}">failed</span>"#,
                    html_escape(error.as_deref().unwrap_or(""))),
                format!(
                    r#"<span class="text-xs text-error">{err}</span>
                       <form method="post" action="/reports/runs/{id}/retry" class="inline"><button class="btn btn-xs btn-outline">Retry</button></form>"#,
                    err = html_escape(&truncate_chars(error.as_deref().unwrap_or("error"), 80)), id = id,
                ),
            ),
            "running" => { any_active = true; (r#"<span class="badge badge-info badge-sm">running…</span>"#.into(), "—".into()) }
            _ => { any_active = true; (r#"<span class="badge badge-ghost badge-sm">queued</span>"#.into(), "—".into()) }
        };
        let who_html = if user.is_admin() {
            format!("<td class=\"text-xs opacity-60\">{}</td>", html_escape(who.as_deref().unwrap_or("")))
        } else { String::new() };
        trs.push_str(&format!(
            r#"<tr><td>{name}</td><td class="uppercase text-xs">{fmt}</td><td class="text-xs opacity-60">{created}</td>{who}<td>{badge}</td><td>{result}</td></tr>"#,
            name = html_escape(&name), fmt = html_escape(&format),
            created = created.format("%Y-%m-%d %H:%M"), who = who_html, badge = badge, result = result,
        ));
    }
    if trs.is_empty() {
        trs = r#"<tr><td colspan="6" class="text-center opacity-60 py-8">No generated reports yet. Queue one from the Reports page.</td></tr>"#.into();
    }
    let who_th = if user.is_admin() { "<th>Requested by</th>" } else { "" };
    // Light auto-refresh while anything is queued/running.
    let refresh = if any_active { r#"<meta http-equiv="refresh" content="10">"# } else { "" };

    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("reports", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    let content = format!(
        r##"<div class="flex justify-between items-center mb-6"><div><h1 class="text-2xl font-bold">Generated Reports</h1>
        <p class="text-base-content/60 text-sm">Background report runs — artifacts are kept for {days} days</p></div>
        <a href="/reports" class="btn btn-sm btn-outline">← Reports</a></div>
        <div class="card bg-base-100 shadow"><div class="card-body p-4 overflow-x-auto">
        <table class="table table-sm"><thead><tr><th>Report</th><th>Format</th><th>Requested</th>{who_th}<th>Status</th><th>Result</th></tr></thead>
        <tbody>{trs}</tbody></table></div></div>"##,
        days = vortex_framework::report_jobs::retention_days(), who_th = who_th, trs = trs,
    );
    let html = format!(
        r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><title>Generated Reports - Remicle</title>{refresh}
<meta name="viewport" content="width=device-width, initial-scale=1.0"><link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script><script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}<main class="flex-1 p-4 lg:p-6 min-w-0">{content}</main></div></body></html>"#,
        refresh = refresh, sidebar = sidebar, content = content,
    );
    Html(html).into_response()
}

/// GET /reports/runs/{id}/download — serve a finished artifact from
/// the FileStore. Only the requester (or an admin) may fetch it.
async fn report_run_download(
    State(state): State<Arc<AppState>>, Db(db): Db, Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let row = sqlx::query(
        "SELECT report_code, report_name, status, store_key, mime, requested_by FROM report_runs WHERE id = $1",
    ).bind(id).fetch_optional(&db).await.ok().flatten();
    let Some(row) = row else {
        return (StatusCode::NOT_FOUND, "Report run not found").into_response();
    };
    let requested_by: uuid::Uuid = row.get("requested_by");
    if requested_by != user.id && !user.is_admin() {
        return (StatusCode::FORBIDDEN, "This report was generated by another user").into_response();
    }
    let status: String = row.get("status");
    let store_key: Option<String> = row.try_get("store_key").ok().flatten();
    let (Some(key), "done") = (store_key, status.as_str()) else {
        return (StatusCode::NOT_FOUND, "Report is not ready").into_response();
    };
    let data = match state.files.get(&db_ctx.db_name, &key).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "Artifact no longer in storage (expired?)").into_response(),
        Err(e) => {
            error!("report artifact fetch failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Storage error").into_response();
        }
    };
    let code: String = row.get("report_code");
    let name: String = row.get("report_name");
    let mime: String = row.try_get::<Option<String>, _>("mime").ok().flatten()
        .unwrap_or_else(|| "application/octet-stream".into());
    let ext = key.rsplit('.').next().unwrap_or("bin");

    let entry = AuditEntry::new(AuditAction::BulkExport, AuditSeverity::Info)
        .with_user(vortex_common::UserId(user.id)).with_username(&user.username)
        .with_database(&db_ctx.db_name).with_resource("report_run", id.to_string()).with_resource_name(&name)
        .with_details(serde_json::json!({"action":"download_generated","format":ext}));
    let _ = state.audit.log(entry).await;

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, mime),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}.{}\"", code, ext)),
        ],
        data,
    ).into_response()
}

/// POST /reports/runs/{id}/retry — re-queue a failed run.
async fn report_run_retry(
    State(state): State<Arc<AppState>>, Db(db): Db, Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let row = sqlx::query("SELECT status, requested_by FROM report_runs WHERE id = $1")
        .bind(id).fetch_optional(&db).await.ok().flatten();
    let Some(row) = row else {
        return (StatusCode::NOT_FOUND, "Report run not found").into_response();
    };
    let requested_by: uuid::Uuid = row.get("requested_by");
    if requested_by != user.id && !user.is_admin() {
        return (StatusCode::FORBIDDEN, "This report was generated by another user").into_response();
    }
    let status: String = row.get("status");
    if status != "failed" {
        return (StatusCode::BAD_REQUEST, "Only failed runs can be retried").into_response();
    }
    let _ = sqlx::query("UPDATE report_runs SET status = 'queued', error = NULL WHERE id = $1")
        .bind(id).execute(&db).await;
    let job = vortex_framework::jobs::NewJob::new(
        vortex_framework::report_jobs::JOB_KIND,
        serde_json::json!({ "run_id": id }),
    ).for_db(&db_ctx.db_name).trace("report_run", &id.to_string()).max_attempts(2);
    if let Err(e) = vortex_framework::jobs::enqueue(&state.db, job).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Could not re-queue: {}", html_escape(&e)))).into_response();
    }
    Redirect::to("/reports/runs").into_response()
}

/// Human-readable byte size for the runs table.
fn human_size(bytes: i64) -> String {
    let b = bytes as f64;
    if b >= 1_048_576.0 { format!("({:.1} MB)", b / 1_048_576.0) }
    else if b >= 1024.0 { format!("({:.0} KB)", b / 1024.0) }
    else { format!("({bytes} B)") }
}

/// First `n` characters, with an ellipsis when cut.
fn truncate_chars(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() }
    else { format!("{}…", s.chars().take(n).collect::<String>()) }
}

/// Wrap report HTML in a printable page with toolbar + export links.
fn report_print_page(def: &vortex_framework::user_reports::ReportDef, inner: &str) -> String {
    let page = if def.orientation == "landscape" { "@page { size: landscape; }" } else { "@page { size: portrait; }" };
    let mut exports = String::new();
    if def.report_type == "tabular" {
        exports.push_str(&format!(r#"<a href="/reports/run/{id}?format=csv" class="btn btn-sm btn-outline">CSV</a><a href="/reports/run/{id}?format=json" class="btn btn-sm btn-outline">JSON</a>"#, id = def.id));
    }
    // Server-side PDF link only when a backend is compiled in; otherwise the
    // browser Print/PDF button covers it.
    if vortex_framework::pdf::available() {
        exports.push_str(&format!(r#"<a href="/reports/run/{id}?format=pdf" class="btn btn-sm btn-outline">PDF</a>"#, id = def.id));
    }
    // Self-hosted CSS inlined — no CDN, so PDF rendering is offline and
    // deterministic (no JS JIT / network race before printToPDF).
    format!(
        r##"<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{name}</title>
<style>{css}
{page}</style></head>
<body class="bg-white text-black p-8">
<div class="no-print fixed top-4 right-4 flex gap-2">{exports}<button onclick="window.print()" class="btn btn-sm btn-primary">Print / PDF</button></div>
<h1 class="text-2xl font-bold mb-1">{name}</h1><p class="text-sm text-gray-500 mb-4">{desc}</p>
{inner}
</body></html>"##,
        name = html_escape(&def.name),
        css = vortex_framework::user_reports::REPORT_CSS,
        page = page, exports = exports,
        desc = html_escape(def.description.as_deref().unwrap_or("")), inner = inner,
    )
}

// ============================================================================
// Dynamic Form View
// ============================================================================

async fn dynamic_form_new(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
) -> Response {
    render_dynamic_form(&db, &user, &model_name, None).await
}

async fn dynamic_form_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model_name, record_id)): Path<(String, uuid::Uuid)>,
) -> Response {
    render_dynamic_form(&db, &user, &model_name, Some(record_id)).await
}

async fn render_dynamic_form(
    db: &PgPool,
    user: &AuthUser,
    model_name: &str,
    record_id: Option<uuid::Uuid>,
) -> Response {
    // Fetch model metadata
    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name FROM ir_model WHERE name = $1 AND is_active = true"
    )
    .bind(model_name)
    .fetch_optional(db)
    .await {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };

    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let table_name: String = model_row.get("table_name");

    if !validate_identifier(&table_name) {
        return (StatusCode::BAD_REQUEST, Html("Invalid model")).into_response();
    }

    // Fetch field definitions
    let fields = sqlx::query(
        "SELECT name, display_name, field_type, selection_options, related_model, widget
         FROM ir_model_field
         WHERE model_id = $1 AND name NOT IN ('id', 'created_at', 'updated_at', 'active')
         ORDER BY sequence, display_name"
    )
    .bind(model_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    // Fetch existing record if editing
    let record_data: std::collections::HashMap<String, String> = if let Some(rid) = record_id {
        let query = format!("SELECT * FROM {} WHERE id = $1", table_name);
        if let Ok(Some(row)) = sqlx::query(&query).bind(rid).fetch_optional(db).await {
            let mut data = std::collections::HashMap::new();
            for col in row.columns() {
                let col_name = col.name();
                let value: String = row.try_get::<String, _>(col_name)
                    .or_else(|_| row.try_get::<Option<String>, _>(col_name).map(|v| v.unwrap_or_default()))
                    .or_else(|_| row.try_get::<i32, _>(col_name).map(|v| v.to_string()))
                    .or_else(|_| row.try_get::<i64, _>(col_name).map(|v| v.to_string()))
                    .or_else(|_| row.try_get::<bool, _>(col_name).map(|v| v.to_string()))
                    .or_else(|_| row.try_get::<uuid::Uuid, _>(col_name).map(|v| v.to_string()))
                    .unwrap_or_default();
                data.insert(col_name.to_string(), value);
            }
            data
        } else {
            std::collections::HashMap::new()
        }
    } else {
        std::collections::HashMap::new()
    };

    // Build form fields HTML
    let mut form_fields = String::new();
    for field in &fields {
        let field_name: String = field.get("name");
        let display_name: String = field.get("display_name");
        let field_type: String = field.get("field_type");
        let selection_options: Option<serde_json::Value> = field.get("selection_options");
        let relation_model: Option<String> = field.get("related_model");
        let widget: Option<String> = field.get("widget");

        let current_value = record_data.get(&field_name).cloned().unwrap_or_default();
        let required_attr = "";  // Can add required logic later based on field metadata
        let readonly_attr = "";

        let input_html = match field_type.as_str() {
            "boolean" => {
                let checked = if current_value == "true" { "checked" } else { "" };
                format!(
                    r#"<input type="checkbox" name="{}" class="checkbox" {} {} />"#,
                    field_name, checked, readonly_attr
                )
            },
            "selection" => {
                let mut options = String::from(r#"<option value="">-- Select --</option>"#);
                if let Some(opts) = &selection_options {
                    if let Some(arr) = opts.as_array() {
                        for item in arr {
                            if let Some(obj) = item.as_object() {
                                let value = obj.get("value").and_then(|v| v.as_str()).unwrap_or("");
                                let label = obj.get("label").and_then(|v| v.as_str()).unwrap_or(value);
                                let selected = if value == current_value { " selected" } else { "" };
                                options.push_str(&format!(r#"<option value="{}"{}>{}  </option>"#, value, selected, label));
                            }
                        }
                    }
                }
                format!(
                    r#"<select name="{}" class="select select-bordered w-full" {} {}>{}</select>"#,
                    field_name, required_attr, readonly_attr, options
                )
            },
            "many2one" => {
                // Fetch related records for dropdown
                if let Some(rel_model) = &relation_model {
                    let rel_table: Option<String> = sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1")
                        .bind(rel_model)
                        .fetch_optional(db)
                        .await
                        .ok()
                        .flatten();

                    if let Some(rel_table) = rel_table {
                        if !validate_identifier(&rel_table) {
                            return (StatusCode::BAD_REQUEST, Html("Invalid related model")).into_response();
                        }
                        // Query includes current value (if any) UNION top 200 by name
                        let rel_query = if !current_value.is_empty() {
                            format!(
                                "(SELECT id, COALESCE(name, id::text) as name FROM {} WHERE id::text = $1) \
                                 UNION \
                                 (SELECT id, COALESCE(name, id::text) as name FROM {} WHERE active = true ORDER BY name LIMIT 200) \
                                 ORDER BY name",
                                rel_table, rel_table
                            )
                        } else {
                            format!("SELECT id, COALESCE(name, id::text) as name FROM {} WHERE active = true ORDER BY name LIMIT 200", rel_table)
                        };
                        let rel_records = if !current_value.is_empty() {
                            sqlx::query(&rel_query).bind(&current_value).fetch_all(db).await.unwrap_or_default()
                        } else {
                            sqlx::query(&rel_query).fetch_all(db).await.unwrap_or_default()
                        };

                        let mut options = String::from(r#"<option value="">-- Select --</option>"#);
                        for rec in &rel_records {
                            let rec_id: uuid::Uuid = rec.get("id");
                            let rec_name: String = rec.get("name");
                            let selected = if rec_id.to_string() == current_value { " selected" } else { "" };
                            options.push_str(&format!(r#"<option value="{}"{}>{}  </option>"#, rec_id, selected, rec_name));
                        }
                        format!(
                            r#"<select name="{}" class="select select-bordered w-full" {} {}>{}</select>"#,
                            field_name, required_attr, readonly_attr, options
                        )
                    } else {
                        format!(
                            r#"<input type="text" name="{}" class="input input-bordered w-full" value="{}" {} {} />"#,
                            field_name, current_value, required_attr, readonly_attr
                        )
                    }
                } else {
                    format!(
                        r#"<input type="text" name="{}" class="input input-bordered w-full" value="{}" {} {} />"#,
                        field_name, current_value, required_attr, readonly_attr
                    )
                }
            },
            "text" => {
                format!(
                    r#"<textarea name="{}" class="textarea textarea-bordered w-full" rows="3" {} {}>{}</textarea>"#,
                    field_name, required_attr, readonly_attr, current_value
                )
            },
            "integer" | "float" => {
                let step = if field_type == "float" { " step=\"0.01\"" } else { "" };
                format!(
                    r#"<input type="number" name="{}" class="input input-bordered w-full" value="{}"{} {} {} />"#,
                    field_name, current_value, step, required_attr, readonly_attr
                )
            },
            "date" => {
                format!(
                    r#"<input type="date" name="{}" class="input input-bordered w-full" value="{}" {} {} />"#,
                    field_name, current_value, required_attr, readonly_attr
                )
            },
            "datetime" => {
                format!(
                    r#"<input type="datetime-local" name="{}" class="input input-bordered w-full" value="{}" {} {} />"#,
                    field_name, current_value.replace(" ", "T"), required_attr, readonly_attr
                )
            },
            _ => {
                // Default to text input
                format!(
                    r#"<input type="text" name="{}" class="input input-bordered w-full" value="{}" {} {} />"#,
                    field_name, current_value, required_attr, readonly_attr
                )
            }
        };

        let required_badge = "";  // Can add required indicator later based on field metadata

        form_fields.push_str(&format!(
            r#"<div class="form-control mb-4">
                <label class="label"><span class="label-text">{} {}</span></label>
                {}
            </div>"#,
            display_name, required_badge, input_html
        ));
    }

    let (action_url, submit_text, title) = if let Some(rid) = record_id {
        (format!("/form/{}/{}", model_name, rid), "Save Changes", format!("Edit {}", model_display_name))
    } else {
        (format!("/form/{}", model_name), "Create", format!("New {}", model_display_name))
    };

    // Build sidebar
    let sidebar_menu = build_sidebar_menu(db, &user.roles, model_name).await;

    let html = format!(
        r##"<!DOCTYPE html>
<html data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
    <script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar-inline').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay-inline').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay-inline" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar-inline').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">
    <aside id="sidebar-inline" class="w-64 bg-base-100 shadow-lg min-h-screen p-4 fixed lg:static top-0 left-0 z-40 h-full -translate-x-full lg:translate-x-0 transition-transform duration-200">
        <div class="text-xl font-bold mb-6"><span class="text-success">re</span><span class="opacity-60">micle</span></div>
        <ul class="menu">{}</ul>
    </aside>
    <main class="flex-1 p-4 lg:p-6 min-w-0">
        <div class="mb-6">
            <a href="/list/{}" class="btn btn-ghost btn-sm">← Back to List</a>
        </div>

        <div class="card bg-base-100 shadow max-w-2xl">
            <div class="card-body">
                <h2 class="card-title">{}</h2>

                <form method="post" action="{}">
                    {}
                    <div class="card-actions justify-end mt-6">
                        <a href="/list/{}" class="btn btn-ghost">Cancel</a>
                        <button type="submit" class="btn btn-primary">{}</button>
                    </div>
                </form>
            </div>
        </div>
    </main>
</div>
</body>
</html>"##,
        title,
        sidebar_menu,
        model_name,
        title,
        action_url,
        form_fields,
        model_name,
        submit_text
    );

    Html(html).into_response()
}

async fn dynamic_form_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(model_name): Path<String>,
    Form(form_data): Form<std::collections::HashMap<String, String>>,
) -> Response {
    // Get table name
    let table_name: Option<String> = sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(table_name) = table_name else {
        return (StatusCode::NOT_FOUND, Html("Model not found")).into_response();
    };

    // Build INSERT query dynamically
    let mut columns = Vec::new();
    let mut placeholders = Vec::new();
    let mut values: Vec<String> = Vec::new();

    for (i, (key, value)) in form_data.iter().enumerate() {
        if key != "id" && !value.is_empty() {
            columns.push(key.clone());
            placeholders.push(format!("${}", i + 1));
            // Handle checkbox values
            let val = if value == "on" { "true".to_string() } else { value.clone() };
            values.push(val);
        }
    }

    if columns.is_empty() {
        return (StatusCode::BAD_REQUEST, Html("No data provided")).into_response();
    }

    let query = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING id",
        table_name,
        columns.join(", "),
        placeholders.join(", ")
    );

    // Build the query with bindings
    let mut q = sqlx::query(&query);
    for val in &values {
        q = q.bind(val);
    }

    match q.fetch_one(&db).await {
        Ok(row) => {
            let new_id: uuid::Uuid = row.get("id");
            Redirect::to(&format!("/form/{}/{}", model_name, new_id)).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response()
        }
    }
}

async fn dynamic_form_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path((model_name, record_id)): Path<(String, uuid::Uuid)>,
    Form(form_data): Form<std::collections::HashMap<String, String>>,
) -> Response {
    // Get table name
    let table_name: Option<String> = sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(table_name) = table_name else {
        return (StatusCode::NOT_FOUND, Html("Model not found")).into_response();
    };

    // Build UPDATE query dynamically
    let mut set_clauses = Vec::new();
    let mut values: Vec<String> = Vec::new();

    for (i, (key, value)) in form_data.iter().enumerate() {
        if key != "id" {
            set_clauses.push(format!("{} = ${}", key, i + 1));
            // Handle checkbox values - if checkbox is unchecked, it won't be in form_data
            let val = if value == "on" { "true".to_string() } else { value.clone() };
            values.push(val);
        }
    }

    if set_clauses.is_empty() {
        return Redirect::to(&format!("/form/{}/{}", model_name, record_id)).into_response();
    }

    let query = format!(
        "UPDATE {} SET {}, updated_at = NOW() WHERE id = ${}",
        table_name,
        set_clauses.join(", "),
        values.len() + 1
    );

    // Build the query with bindings
    let mut q = sqlx::query(&query);
    for val in &values {
        q = q.bind(val);
    }
    q = q.bind(record_id);

    match q.execute(&db).await {
        Ok(_) => Redirect::to(&format!("/form/{}/{}", model_name, record_id)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response(),
    }
}

// API endpoints for country/state data
async fn api_countries(State(state): State<Arc<AppState>>, Db(db): Db) -> Response {
    let countries = sqlx::query("SELECT id, code, name FROM countries WHERE active = true ORDER BY sequence, name")
        .fetch_all(&db).await.unwrap_or_default();

    let data: Vec<serde_json::Value> = countries.iter().map(|c| {
        serde_json::json!({
            "id": c.get::<uuid::Uuid, _>("id").to_string(),
            "code": c.get::<String, _>("code"),
            "name": c.get::<String, _>("name")
        })
    }).collect();

    axum::Json(data).into_response()
}

async fn api_states(State(state): State<Arc<AppState>>, Db(db): Db, Path(country_id): Path<uuid::Uuid>) -> Response {
    let states = sqlx::query("SELECT id, code, name FROM states WHERE country_id = $1 AND active = true ORDER BY name")
        .bind(country_id).fetch_all(&db).await.unwrap_or_default();

    let data: Vec<serde_json::Value> = states.iter().map(|s| {
        serde_json::json!({
            "id": s.get::<uuid::Uuid, _>("id").to_string(),
            "code": s.get::<String, _>("code"),
            "name": s.get::<String, _>("name")
        })
    }).collect();

    axum::Json(data).into_response()
}

/// Query for the many2one typeahead: an opaque signed descriptor `src` plus
/// the partial text `q`. See [`vortex_framework::form::LookupSource`].
#[derive(serde::Deserialize)]
struct LookupParams {
    src: String,
    #[serde(default)]
    q: String,
}

/// `GET /api/lookup?src=<signed>&q=<text>` — suggestion feed for reference
/// fields. `src` is a server-signed [`LookupSource`]; an unverifiable token is
/// refused (empty result), so a session user can never search an arbitrary
/// table. Session-authenticated and tenant-scoped like any other UI endpoint.
async fn api_lookup(Db(db): Db, Query(params): Query<LookupParams>) -> Response {
    let Some(src) = vortex_framework::form::LookupSource::decode(&params.src) else {
        return axum::Json(serde_json::json!({ "results": [] })).into_response();
    };
    let results: Vec<serde_json::Value> = src
        .search(&db, &params.q)
        .await
        .into_iter()
        .map(|(id, label)| serde_json::json!({ "id": id, "label": label }))
        .collect();
    axum::Json(serde_json::json!({ "results": results })).into_response()
}

#[cfg(test)]
mod tenant_host_tests {
    use super::*;

    fn hdrs(host: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, host.parse().unwrap());
        h
    }

    fn dbs(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn request_host_strips_port_and_lowercases() {
        assert_eq!(request_host(&hdrs("Gaia.Vortex.Com:443")), Some("gaia.vortex.com".into()));
        assert_eq!(request_host(&hdrs("localhost:3000")), Some("localhost".into()));
        assert_eq!(request_host(&hdrs("[::1]:3000")), Some("::1".into()));
        assert_eq!(request_host(&HeaderMap::new()), None);
    }

    #[test]
    fn local_hosts_detected() {
        assert!(is_local_host("localhost"));
        assert!(is_local_host("127.0.0.1"));
        assert!(is_local_host("::1"));
        assert!(is_local_host("gaia.localhost"));
        assert!(!is_local_host("gaia.vortex.com"));
        assert!(!is_local_host("192.168.1.5"));
    }

    #[test]
    fn subdomain_filter_matches_tenant() {
        let all = dbs(&["gaia", "remicle", "vortex"]);
        assert_eq!(host_filtered_databases("^%h$", "gaia.vortex.com", &all), dbs(&["gaia"]));
        assert_eq!(host_filtered_databases("^%h$", "remicle.vortex.com", &all), dbs(&["remicle"]));
        // Unknown subdomain and bare IPs match nothing
        assert!(host_filtered_databases("^%h$", "nope.vortex.com", &all).is_empty());
        assert!(host_filtered_databases("^%h$", "192.168.1.5", &all).is_empty());
    }

    #[test]
    fn prefix_filter_supports_db_name_prefix() {
        let all = dbs(&["vortex_gaia", "vortex_remicle"]);
        assert_eq!(
            host_filtered_databases("^vortex_%h$", "gaia.vortex.com", &all),
            dbs(&["vortex_gaia"])
        );
    }

    #[test]
    fn hostile_host_values_cannot_widen_the_regex() {
        let all = dbs(&["gaia", "remicle"]);
        // A crafted Host whose first label is a regex wildcard must not
        // match every database once %h is escaped.
        assert!(host_filtered_databases("^%h$", ".*.vortex.com", &all).is_empty());
        assert!(host_filtered_databases("^%h$", "gaia|remicle.vortex.com", &all).is_empty());
    }
}
