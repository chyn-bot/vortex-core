//! # Outbound webhooks — HMAC-signed event delivery over the job queue
//!
//! External systems integrate with Vortex by subscribing to **events**. An
//! endpoint (`webhook_endpoints`) registers a URL and the event types it cares
//! about (empty = all). When the core [`emit`]s a matching event it enqueues a
//! `webhook.deliver` [job](crate::jobs) per endpoint, so delivery inherits the
//! durable queue's retries, exponential backoff, and dead-lettering for free —
//! a flaky receiver never blocks the request that produced the event.
//!
//! The delivery handler signs the JSON body with the endpoint's secret
//! (HMAC-SHA256 → `X-Vortex-Signature: sha256=<hex>`), POSTs it, and records
//! the attempt in `webhook_deliveries`. Secrets are encrypted at rest with the
//! same AES-256-GCM scheme as SMTP passwords (`vortex_security::crypto`).
//!
//! Wiring: the host registers the handler via [`register_handler`] at startup
//! (alongside `mail.send`), and call sites emit events with [`emit`]. The API
//! record handlers emit `record.{created,updated,deleted}`; plugins can emit
//! their own event types through the SDK.

use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use vortex_security::crypto;

use crate::jobs::{enqueue, JobContext, JobRegistry, NewJob};

/// The job `kind` used for webhook delivery.
pub const DELIVER_KIND: &str = "webhook.deliver";

/// A registered subscriber. The secret is kept encrypted; it is only decrypted
/// inside the delivery handler to sign a payload.
#[derive(Debug, Clone)]
pub struct WebhookEndpoint {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub event_types: Vec<String>,
    pub active: bool,
    pub last_delivery_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_status: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

fn row_to_endpoint(r: &sqlx::postgres::PgRow) -> WebhookEndpoint {
    WebhookEndpoint {
        id: r.get("id"),
        name: r.get("name"),
        url: r.get("url"),
        event_types: r.try_get("event_types").unwrap_or_default(),
        active: r.get("active"),
        last_delivery_at: r.try_get("last_delivery_at").ok().flatten(),
        last_status: r.try_get("last_status").ok().flatten(),
        created_at: r.get("created_at"),
    }
}

/// List endpoints (newest first) for the admin UI.
pub async fn list_endpoints(db: &PgPool) -> Vec<WebhookEndpoint> {
    sqlx::query(
        "SELECT id, name, url, event_types, active, last_delivery_at, last_status, created_at \
         FROM webhook_endpoints ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(row_to_endpoint)
    .collect()
}

/// Fetch one endpoint by id.
pub async fn get_endpoint(db: &PgPool, id: Uuid) -> Option<WebhookEndpoint> {
    sqlx::query(
        "SELECT id, name, url, event_types, active, last_delivery_at, last_status, created_at \
         FROM webhook_endpoints WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .as_ref()
    .map(row_to_endpoint)
}

/// Encrypt a signing secret with the master key, or `None` if empty.
fn encrypt_secret(secret: &str) -> Option<Vec<u8>> {
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }
    let key = crypto::master_key();
    crypto::encrypt_str(secret, &key).ok()
}

/// Create an endpoint. `event_types` empty means "all events".
pub async fn create_endpoint(
    db: &PgPool,
    name: &str,
    url: &str,
    secret: &str,
    event_types: &[String],
    created_by: Option<Uuid>,
) -> Result<Uuid, String> {
    let secret_enc = encrypt_secret(secret);
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO webhook_endpoints (name, url, secret_enc, event_types, created_by) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(name)
    .bind(url)
    .bind(secret_enc)
    .bind(event_types)
    .bind(created_by)
    .fetch_one(db)
    .await
    .map_err(|e| format!("insert failed: {e}"))
}

/// Update an endpoint. The secret is only rewritten when a non-empty value is
/// supplied (so editing other fields keeps the existing secret).
pub async fn update_endpoint(
    db: &PgPool,
    id: Uuid,
    name: &str,
    url: &str,
    secret: &str,
    event_types: &[String],
    active: bool,
) -> Result<(), String> {
    if let Some(enc) = encrypt_secret(secret) {
        sqlx::query(
            "UPDATE webhook_endpoints SET name=$1, url=$2, secret_enc=$3, event_types=$4, \
             active=$5, updated_at=NOW() WHERE id=$6",
        )
        .bind(name).bind(url).bind(enc).bind(event_types).bind(active).bind(id)
        .execute(db).await.map_err(|e| format!("update failed: {e}"))?;
    } else {
        sqlx::query(
            "UPDATE webhook_endpoints SET name=$1, url=$2, event_types=$3, active=$4, \
             updated_at=NOW() WHERE id=$5",
        )
        .bind(name).bind(url).bind(event_types).bind(active).bind(id)
        .execute(db).await.map_err(|e| format!("update failed: {e}"))?;
    }
    Ok(())
}

/// Delete an endpoint (its delivery log cascades).
pub async fn delete_endpoint(db: &PgPool, id: Uuid) -> Result<(), String> {
    sqlx::query("DELETE FROM webhook_endpoints WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(|e| format!("delete failed: {e}"))?;
    Ok(())
}

/// Recent delivery attempts for one endpoint (for the admin detail view).
pub async fn recent_deliveries(db: &PgPool, endpoint_id: Uuid, limit: i64) -> Vec<Value> {
    sqlx::query(
        "SELECT event_type, status, status_code, duration_ms, error, created_at \
         FROM webhook_deliveries WHERE endpoint_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(endpoint_id)
    .bind(limit)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|r| {
        json!({
            "event_type": r.get::<String, _>("event_type"),
            "status": r.get::<String, _>("status"),
            "status_code": r.try_get::<Option<i32>, _>("status_code").ok().flatten(),
            "duration_ms": r.try_get::<Option<i32>, _>("duration_ms").ok().flatten(),
            "error": r.try_get::<Option<String>, _>("error").ok().flatten(),
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        })
    })
    .collect()
}

/// Emit an event: enqueue a `webhook.deliver` job for every active endpoint in
/// `tenant_db` subscribed to `event_type` (or to all events). Jobs are written
/// to `jobs_pool` (the primary DB, where the queue lives) and carry `db_name`
/// so the worker resolves the tenant pool to load the endpoint and log the
/// delivery. Returns how many jobs were enqueued. Best-effort: emitting never
/// fails the originating operation.
pub async fn emit(
    jobs_pool: &PgPool,
    tenant_db: &PgPool,
    db_name: &str,
    event_type: &str,
    data: Value,
) -> usize {
    // `event_types = '{}'` (all) OR the array contains this event.
    let endpoints = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM webhook_endpoints \
         WHERE active = true AND (cardinality(event_types) = 0 OR $1 = ANY(event_types))",
    )
    .bind(event_type)
    .fetch_all(tenant_db)
    .await
    .unwrap_or_default();

    let mut enqueued = 0;
    for endpoint_id in endpoints {
        let job = NewJob::new(
            DELIVER_KIND,
            json!({ "endpoint_id": endpoint_id, "event_type": event_type, "data": data }),
        )
        .for_db(db_name)
        .trace("webhook_endpoint", &endpoint_id.to_string());
        if enqueue(jobs_pool, job).await.is_ok() {
            enqueued += 1;
        }
    }
    if enqueued > 0 {
        tracing::debug!(event_type, enqueued, "webhook events enqueued");
    }
    enqueued
}

/// Register the `webhook.deliver` handler on the job registry. Called at
/// startup beside [`crate::jobs::register_core_handlers`].
pub fn register_handler(reg: &mut JobRegistry) {
    reg.register(DELIVER_KIND, |ctx: JobContext| async move {
        deliver(ctx).await
    });
}

/// One delivery attempt. Loads the endpoint from the tenant pool, signs the
/// body, POSTs it, and records the outcome. A non-2xx response or transport
/// error returns `Err`, which the queue turns into a retry (then dead-letter).
async fn deliver(ctx: JobContext) -> Result<(), String> {
    let p = &ctx.payload;
    let endpoint_id = p
        .get("endpoint_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("webhook.deliver: missing endpoint_id")?;
    let event_type = p.get("event_type").and_then(|v| v.as_str()).unwrap_or("event").to_string();
    let data = p.get("data").cloned().unwrap_or(Value::Null);

    let pool = ctx.pool().await;

    // Load url + secret. A deleted/disabled endpoint => succeed (nothing to do).
    let row = sqlx::query("SELECT url, secret_enc, active FROM webhook_endpoints WHERE id = $1")
        .bind(endpoint_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| format!("endpoint lookup failed: {e}"))?;
    let Some(row) = row else { return Ok(()) };
    if !row.get::<bool, _>("active") {
        return Ok(());
    }
    let url: String = row.get("url");
    let secret_enc: Option<Vec<u8>> = row.try_get("secret_enc").ok().flatten();

    // Canonical body the receiver verifies against the signature.
    let body = json!({
        "event": event_type,
        "data": data,
        "delivery_id": ctx.job_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;

    let signature = secret_enc.as_ref().and_then(|enc| {
        let key = crypto::master_key();
        crypto::decrypt_str(enc, &key)
            .ok()
            .map(|secret| crypto::hmac_sha256_hex(secret.as_bytes(), &body_bytes))
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let mut req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Vortex-Webhook/1")
        .header("X-Vortex-Event", &event_type)
        .header("X-Vortex-Delivery", ctx.job_id.to_string())
        .body(body_bytes);
    if let Some(sig) = &signature {
        req = req.header("X-Vortex-Signature", format!("sha256={sig}"));
    }

    let started = std::time::Instant::now();
    let result = req.send().await;
    let duration_ms = started.elapsed().as_millis() as i32;

    let (status, code, err): (&str, Option<i32>, Option<String>) = match result {
        Ok(resp) => {
            let code = resp.status().as_u16() as i32;
            if resp.status().is_success() {
                ("success", Some(code), None)
            } else {
                ("failed", Some(code), Some(format!("HTTP {code}")))
            }
        }
        Err(e) => ("failed", None, Some(e.to_string())),
    };

    // Record the attempt and update the endpoint summary (best-effort).
    let _ = sqlx::query(
        "INSERT INTO webhook_deliveries (endpoint_id, event_type, status, status_code, duration_ms, error) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(endpoint_id).bind(&event_type).bind(status).bind(code).bind(duration_ms).bind(&err)
    .execute(&pool).await;
    let _ = sqlx::query(
        "UPDATE webhook_endpoints SET last_delivery_at = NOW(), last_status = $1 WHERE id = $2",
    )
    .bind(status).bind(endpoint_id).execute(&pool).await;

    if status == "success" {
        Ok(())
    } else {
        Err(err.unwrap_or_else(|| "delivery failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use vortex_security::crypto;

    #[test]
    fn signature_is_stable_and_keyed() {
        let body = br#"{"event":"record.created"}"#;
        let a = crypto::hmac_sha256_hex(b"secret", body);
        let b = crypto::hmac_sha256_hex(b"secret", body);
        let c = crypto::hmac_sha256_hex(b"other", body);
        assert_eq!(a, b, "same key+body => same signature");
        assert_ne!(a, c, "different key => different signature");
        assert_eq!(a.len(), 64, "sha256 hex is 64 chars");
    }

    #[test]
    fn secret_round_trips_through_encryption() {
        let key = crypto::master_key();
        let enc = crypto::encrypt_str("whsec_abc", &key).unwrap();
        assert_eq!(crypto::decrypt_str(&enc, &key).unwrap(), "whsec_abc");
    }
}
