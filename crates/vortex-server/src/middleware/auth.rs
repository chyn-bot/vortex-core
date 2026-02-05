//! Authentication middleware

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vortex_common::{CompanyId, Context, UserId, VortexResult, VortexError};

use crate::state::AppState;

/// JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,         // User ID
    pub sid: String,         // Session ID
    pub cid: Option<String>, // Company ID
    pub roles: Vec<String>,  // User roles
    pub exp: i64,            // Expiration
    pub iat: i64,            // Issued at
}

/// Generate a JWT token for an authenticated user
pub fn generate_jwt(
    user_id: UserId,
    session_id: Uuid,
    company_id: Option<CompanyId>,
    roles: Vec<String>,
    jwt_secret: &str,
    expiry_hours: i64,
) -> VortexResult<String> {
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::hours(expiry_hours);

    let claims = Claims {
        sub: user_id.0.to_string(),
        sid: session_id.to_string(),
        cid: company_id.map(|c| c.0.to_string()),
        roles,
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| VortexError::Internal(format!("JWT encoding failed: {}", e)))
}

/// Authentication layer
#[derive(Clone)]
pub struct AuthLayer {
    pub jwt_secret: Arc<String>,
}

impl AuthLayer {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            jwt_secret: Arc::new(secret.into()),
        }
    }
}

/// Extract token from cookie header
fn extract_token_from_cookie(request: &Request) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("auth_token="))
                .map(|s| s.trim_start_matches("auth_token=").to_string())
        })
}

/// Extract and validate authentication from request
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Try Authorization header first, then cookie
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => header[7..].to_string(),
        _ => {
            // Try cookie
            match extract_token_from_cookie(&request) {
                Some(t) => t,
                None => {
                    // No token - set anonymous context
                    let ctx = Context::anonymous();
                    request.extensions_mut().insert(ctx);
                    return Ok(next.run(request).await);
                }
            }
        }
    };

    // Decode JWT
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let claims = token_data.claims;

    // Validate session
    let session_id = Uuid::parse_str(&claims.sid).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let _session = state
        .sessions
        .validate_session(session_id)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Build context
    let user_id = UserId(Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::UNAUTHORIZED)?);

    let company_id = claims
        .cid
        .as_ref()
        .and_then(|c| Uuid::parse_str(c).ok())
        .map(CompanyId);

    // Get roles from JWT claims (already validated)
    let roles = claims.roles.clone();

    let ctx = Context::authenticated(user_id, company_id.unwrap_or(CompanyId(Uuid::nil())))
        .with_roles(roles)
        .with_session(session_id);

    // Add source IP and user agent
    let source_ip = request
        .headers()
        .get("x-forwarded-for")
        .or_else(|| request.headers().get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let ctx = if let Some(ip) = source_ip {
        ctx.with_source_ip(ip)
    } else {
        ctx
    };

    let ctx = if let Some(ua) = user_agent {
        ctx.with_user_agent(ua)
    } else {
        ctx
    };

    request.extensions_mut().insert(ctx);
    Ok(next.run(request).await)
}

/// Require authentication (returns 401 for API)
pub async fn require_auth(
    ctx: Option<axum::Extension<Context>>,
) -> Result<Context, StatusCode> {
    match ctx {
        Some(axum::Extension(ctx)) if ctx.user_id.is_some() => Ok(ctx),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Middleware to require authentication for HTML pages (redirects to login)
pub async fn require_auth_html(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Try to extract token from cookie
    let token = extract_token_from_cookie(&request);

    let is_authenticated = if let Some(token) = token {
        // Validate JWT
        decode::<Claims>(
            &token,
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .is_ok()
    } else {
        false
    };

    if is_authenticated {
        next.run(request).await
    } else {
        Redirect::to("/login").into_response()
    }
}

/// Check if user has a specific role
pub fn check_role(ctx: &Context, role: &str) -> bool {
    ctx.has_role(role)
}

/// Check if user is admin (System Administrator or Administrator)
pub fn is_admin(ctx: &Context) -> bool {
    ctx.has_any_role(&["System Administrator", "Administrator"])
}

/// Check if user is system admin
pub fn is_system_admin(ctx: &Context) -> bool {
    ctx.has_role("System Administrator")
}
