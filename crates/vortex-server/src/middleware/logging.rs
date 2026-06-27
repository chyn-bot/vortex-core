//! Request logging middleware for compliance/audit

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

/// Logging middleware that records all API requests
pub async fn logging_middleware(request: Request, next: Next) -> Response {
    let request_id = Uuid::now_v7();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let start = Instant::now();

    // Get client info (convert to owned strings before moving request)
    let source_ip = request
        .headers()
        .get("x-forwarded-for")
        .or_else(|| request.headers().get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Execute request
    let response = next.run(request).await;

    let duration = start.elapsed();
    let status = response.status();

    // Log based on status
    if status.is_server_error() {
        warn!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %status.as_u16(),
            duration_ms = %duration.as_millis(),
            source_ip = %source_ip,
            "Request failed"
        );
    } else {
        info!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %status.as_u16(),
            duration_ms = %duration.as_millis(),
            source_ip = %source_ip,
            "Request completed"
        );
    }

    response
}
