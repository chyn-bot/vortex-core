//! API response types

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use vortex_common::VortexError;

/// Standard API response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiErrorDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<PaginationInfo>,
}

impl<T: Serialize> ApiResponse<T> {
    /// Create a success response
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            pagination: None,
        }
    }

    /// Create a success response with pagination
    pub fn paginated(data: T, pagination: PaginationInfo) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            pagination: Some(pagination),
        }
    }
}

impl ApiResponse<()> {
    /// Create an error response
    pub fn error(code: &str, message: &str) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(ApiErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
                details: None,
            }),
            pagination: None,
        }
    }
}

/// Error detail in API response
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Pagination information
#[derive(Debug, Serialize, Deserialize)]
pub struct PaginationInfo {
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    pub total_pages: u64,
}

impl PaginationInfo {
    pub fn new(total: u64, page: u64, per_page: u64) -> Self {
        let total_pages = (total + per_page - 1) / per_page;
        Self {
            total,
            page,
            per_page,
            total_pages,
        }
    }
}

/// API error type
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    // Common errors
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
    }

    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Authentication required")
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "FORBIDDEN", message)
    }

    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", format!("{} not found", resource.into()))
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "CONFLICT", message)
    }

    pub fn rate_limited() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED", "Too many requests")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(ApiErrorDetail {
                code: self.code,
                message: self.message,
                details: self.details,
            }),
            pagination: None,
        };

        (self.status, Json(body)).into_response()
    }
}

impl From<VortexError> for ApiError {
    fn from(err: VortexError) -> Self {
        match err {
            VortexError::RecordNotFound { model, id } => {
                ApiError::not_found(format!("{} with id {}", model, id))
            }
            VortexError::AuthenticationFailed { .. } => ApiError::unauthorized(),
            VortexError::AccessDenied { action, resource } => {
                ApiError::forbidden(format!("Cannot {} on {}", action, resource))
            }
            VortexError::SessionInvalid => ApiError::unauthorized(),
            VortexError::InsufficientPermissions { required, .. } => {
                ApiError::forbidden(format!("Requires permission: {}", required))
            }
            VortexError::ValidationFailed(msg) => ApiError::bad_request(msg),
            VortexError::InvalidFieldValue { field, reason } => {
                ApiError::bad_request(format!("Invalid {}: {}", field, reason))
            }
            VortexError::RequiredFieldMissing(field) => {
                ApiError::bad_request(format!("Missing required field: {}", field))
            }
            VortexError::ConstraintViolation(msg) => ApiError::conflict(msg),
            VortexError::RateLimitExceeded { .. } => ApiError::rate_limited(),
            VortexError::SecurityPolicyViolation(msg) => ApiError::forbidden(msg),
            _ => ApiError::internal(err.to_string()),
        }
    }
}

/// Helper type for API results
pub type ApiResult<T> = Result<Json<ApiResponse<T>>, ApiError>;
