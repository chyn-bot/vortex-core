//! Authentication views

use askama::Template;
use axum::{
    extract::{ConnectInfo, Form, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use vortex_security::Credentials;

use super::common::generate_csrf_token;
use crate::db::user_lookup::get_user_roles;
use crate::middleware::auth::generate_jwt;
use crate::state::AppState;

/// Login page template
#[derive(Template)]
#[template(path = "pages/login.html")]
pub struct LoginTemplate {
    pub csrf_token: String,
}

/// Login form data
#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub remember: Option<String>,
}

/// Show login page
pub async fn login_page() -> impl IntoResponse {
    let template = LoginTemplate {
        csrf_token: generate_csrf_token(),
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

/// Handle login form submission
pub async fn login_submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // Validate input
    if form.username.is_empty() || form.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Html("<span class=\"text-error\">Username and password are required</span>"),
        )
            .into_response();
    }

    // Get source IP and user agent for audit
    let source_ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    // Create credentials
    let credentials = Credentials::new(&form.username, &form.password);

    // Authenticate
    match state.auth.authenticate(&credentials, &source_ip, user_agent).await {
        Ok(auth_result) => {
            // Check if password expired
            if auth_result.password_expired {
                return (
                    StatusCode::OK,
                    Html("<span class=\"text-warning\">Password expired. Please change your password.</span>"),
                )
                    .into_response();
            }

            // Check if MFA is required
            if auth_result.requires_mfa {
                return (
                    StatusCode::OK,
                    Html("<span class=\"text-info\">MFA verification required</span>"),
                )
                    .into_response();
            }

            // Get user roles for JWT
            let roles = get_user_roles(&state.db, auth_result.user_id)
                .await
                .unwrap_or_default();

            // Generate JWT token
            let token = match generate_jwt(
                auth_result.user_id,
                auth_result.session.id,
                auth_result.session.company_id,
                roles,
                &state.jwt_secret,
                24, // 24 hours
            ) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("Failed to generate JWT: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Html("<span class=\"text-error\">Authentication error</span>"),
                    )
                        .into_response();
                }
            };

            // Set cookie and redirect
            let cookie_value = if form.remember.is_some() {
                // Remember me: 30 day expiry
                format!(
                    "auth_token={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000",
                    token
                )
            } else {
                // Session cookie (expires when browser closes)
                format!(
                    "auth_token={}; Path=/; HttpOnly; SameSite=Strict",
                    token
                )
            };

            let mut response_headers = HeaderMap::new();
            response_headers.insert(
                header::SET_COOKIE,
                cookie_value.parse().unwrap(),
            );
            response_headers.insert(
                "HX-Redirect",
                HeaderValue::from_static("/home"),
            );

            (StatusCode::OK, response_headers, Html("")).into_response()
        }
        Err(e) => {
            // Handle specific error cases
            let error_msg = match &e {
                vortex_common::VortexError::SecurityPolicyViolation(msg) if msg.contains("locked") => {
                    "Account is temporarily locked due to too many failed attempts"
                }
                vortex_common::VortexError::AuthenticationFailed { .. } => {
                    "Invalid username or password"
                }
                _ => {
                    tracing::error!("Login error: {}", e);
                    "Authentication failed"
                }
            };

            (
                StatusCode::UNAUTHORIZED,
                Html(format!("<span class=\"text-error\">{}</span>", error_msg)),
            )
                .into_response()
        }
    }
}

/// Handle logout
pub async fn logout(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<vortex_common::Context>,
) -> impl IntoResponse {
    // Revoke session if authenticated
    if let (Some(user_id), Some(session_id)) = (ctx.user_id, ctx.session_id) {
        if let Err(e) = state.auth.logout(session_id, user_id).await {
            tracing::warn!("Failed to revoke session on logout: {}", e);
        }
    }

    // Clear the auth cookie
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        "auth_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            .parse()
            .unwrap(),
    );
    headers.insert("HX-Redirect", HeaderValue::from_static("/login"));

    (StatusCode::OK, headers)
}
