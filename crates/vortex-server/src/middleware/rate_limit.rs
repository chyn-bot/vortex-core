//! Rate limiting middleware.
//!
//! Two backends behind one interface:
//!
//! - [`Backend::Memory`] — process-local buckets. Correct on a single node;
//!   used in tests and single-instance deployments.
//! - [`Backend::Postgres`] — a shared counter table (`rate_limit_bucket`) so the
//!   limit holds across *every* app instance pointed at the same database.
//!
//! The Postgres backend is what makes horizontal scale-out honest: two app
//! nodes behind a load balancer enforce **one** combined limit, not two
//! independent ones. Without it, an attacker just spreads a brute-force across
//! nodes and each node counts only its own share. The counters that protect the
//! login / intake / mobile / portal / data-API endpoints are the last piece of
//! per-instance state in the request path — everything else (sessions, cache
//! invalidation, job claiming) is already shared through Postgres.
//!
//! Windows are fixed (each `window` is an independent counter keyed by its start
//! epoch). That admits the classic up-to-2× burst at a window boundary, which is
//! fine for abuse protection — it still bounds the sustained rate. The check is
//! a single atomic UPSERT.
//!
//! ## Fail-open vs fail-closed
//!
//! On a limiter DB error the backend can either **fail open** (allow the
//! request — a DB blip must not lock legitimate users out) or **fail closed**
//! (reject with 429 — an abuse-sensitive endpoint must not lose its guard when
//! the counter is unavailable). Construct with [`RateLimiter::postgres`] for
//! fail-open, or [`RateLimiter::postgres_strict`] for fail-closed. The data API
//! and other abuse-sensitive scopes use the strict variant so the rate guard is
//! never silently disabled — the posture this codebase's cloud-risk assessment
//! commits to.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Window duration
    pub window: Duration,
    /// Whether to apply per-user limits
    pub per_user: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window: Duration::from_secs(60),
            per_user: true,
        }
    }
}

/// Rate limiter state
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimitConfig,
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    /// Process-local counters (single node / tests).
    Memory(Arc<RwLock<HashMap<String, RateBucket>>>),
    /// Shared counters in `rate_limit_bucket`, keyed by `scope` so distinct
    /// limiters don't collide. All app instances on this DB share the count.
    /// `fail_open` decides behaviour when the counter query errors.
    Postgres {
        pool: sqlx::PgPool,
        scope: Arc<str>,
        fail_open: bool,
    },
}

#[derive(Debug)]
struct RateBucket {
    count: u32,
    window_start: Instant,
}

impl RateLimiter {
    /// Process-local limiter. Correct on one node; used in tests and
    /// single-instance deployments.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            backend: Backend::Memory(Arc::new(RwLock::new(HashMap::new()))),
        }
    }

    /// Shared, multi-instance limiter backed by `rate_limit_bucket`, **fail
    /// open**: a limiter DB error allows the request. Use for endpoints where a
    /// DB blip must never lock legitimate users out (e.g. interactive login).
    pub fn postgres(config: RateLimitConfig, pool: sqlx::PgPool, scope: impl Into<Arc<str>>) -> Self {
        Self {
            config,
            backend: Backend::Postgres { pool, scope: scope.into(), fail_open: true },
        }
    }

    /// Shared, multi-instance limiter backed by `rate_limit_bucket`, **fail
    /// closed**: a limiter DB error rejects the request with 429. Use for
    /// abuse-sensitive scopes (the data API) where losing the guard is worse
    /// than briefly rejecting traffic — and where a downed counter DB means the
    /// request's own data query would fail anyway.
    pub fn postgres_strict(
        config: RateLimitConfig,
        pool: sqlx::PgPool,
        scope: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            config,
            backend: Backend::Postgres { pool, scope: scope.into(), fail_open: false },
        }
    }

    /// Check if a request from `key` (typically a client IP or token digest) is
    /// allowed, and count it against the current window.
    pub async fn check(&self, key: &str) -> bool {
        match &self.backend {
            Backend::Memory(buckets) => self.check_memory(buckets, key).await,
            Backend::Postgres { pool, scope, fail_open } => {
                self.check_postgres(pool, scope, *fail_open, key).await
            }
        }
    }

    async fn check_memory(
        &self,
        buckets: &Arc<RwLock<HashMap<String, RateBucket>>>,
        key: &str,
    ) -> bool {
        let mut buckets = buckets.write().await;
        let now = Instant::now();

        let bucket = buckets.entry(key.to_string()).or_insert(RateBucket {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(bucket.window_start) >= self.config.window {
            bucket.count = 0;
            bucket.window_start = now;
        }

        if bucket.count >= self.config.max_requests {
            return false;
        }

        bucket.count += 1;
        true
    }

    async fn check_postgres(
        &self,
        pool: &sqlx::PgPool,
        scope: &str,
        fail_open: bool,
        key: &str,
    ) -> bool {
        let window_secs = self.config.window.as_secs().max(1) as i64;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let window_start = (now / window_secs) * window_secs;

        // One atomic increment for the current window, shared across instances.
        // `count` is INT4, so decode as i32 — decoding int4 as i64 would error
        // and trip the fail path on every request.
        let count: i32 = match sqlx::query_scalar(
            "INSERT INTO rate_limit_bucket (scope, client_key, window_start, count) \
             VALUES ($1, $2, $3, 1) \
             ON CONFLICT (scope, client_key, window_start) \
             DO UPDATE SET count = rate_limit_bucket.count + 1 \
             RETURNING count",
        )
        .bind(scope)
        .bind(key)
        .bind(window_start)
        .fetch_one(pool)
        .await
        {
            Ok(c) => c,
            Err(e) => {
                if fail_open {
                    // A limiter DB blip (or a DB missing the migration) must not
                    // lock legitimate users out of this endpoint.
                    tracing::warn!(error = %e, scope, "rate-limit check failed; allowing request (fail-open)");
                    return true;
                } else {
                    // Abuse-sensitive scope: reject rather than run unguarded.
                    tracing::warn!(error = %e, scope, "rate-limit check failed; rejecting request (fail-closed)");
                    return false;
                }
            }
        };

        // On the first request of a new window for this key, drop the key's
        // older windows so the table self-prunes for active clients.
        if count == 1 {
            let _ = sqlx::query(
                "DELETE FROM rate_limit_bucket \
                 WHERE scope = $1 AND client_key = $2 AND window_start < $3",
            )
            .bind(scope)
            .bind(key)
            .bind(window_start)
            .execute(pool)
            .await;
        }

        count <= self.config.max_requests as i32
    }

    /// Remove expired buckets. Only meaningful for the memory backend; the
    /// Postgres backend self-prunes per key and is swept by [`Self::spawn_pruner`].
    pub async fn cleanup(&self) {
        if let Backend::Memory(buckets) = &self.backend {
            let mut buckets = buckets.write().await;
            let now = Instant::now();
            let window = self.config.window;
            buckets.retain(|_, bucket| now.duration_since(bucket.window_start) < window * 2);
        }
    }

    /// Delete stale windows for this limiter's scope (Postgres backend only), so
    /// abandoned client keys don't accumulate rows.
    pub async fn prune_stale(&self) {
        if let Backend::Postgres { pool, scope, .. } = &self.backend {
            let window_secs = self.config.window.as_secs().max(1) as i64;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let cutoff = now - window_secs * 2;
            let _ = sqlx::query("DELETE FROM rate_limit_bucket WHERE scope = $1 AND window_start < $2")
                .bind(&**scope)
                .bind(cutoff)
                .execute(pool)
                .await;
        }
    }

    /// Spawn a background task that periodically prunes stale windows for this
    /// limiter's scope. No-op for the memory backend. Call once at startup.
    pub fn spawn_pruner(&self) {
        if let Backend::Postgres { .. } = &self.backend {
            let this = self.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(300));
                ticker.tick().await; // consume the immediate first tick
                loop {
                    ticker.tick().await;
                    this.prune_stale().await;
                }
            });
        }
    }
}

/// Rate limiting middleware — checks the RateLimiter from request extensions.
pub async fn rate_limit_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let client_id = request
        .headers()
        .get("x-forwarded-for")
        .or_else(|| request.headers().get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        // A comma-separated XFF chain starts with the origin client; key on it.
        .map(|v| v.split(',').next().unwrap_or(v).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let limiter = request.extensions().get::<RateLimiter>().cloned();

    if let Some(limiter) = limiter {
        if !limiter.check(&client_id).await {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(max: u32, window: Duration) -> RateLimitConfig {
        RateLimitConfig { max_requests: max, window, per_user: false }
    }

    #[tokio::test]
    async fn memory_allows_up_to_max_then_denies() {
        let rl = RateLimiter::new(cfg(2, Duration::from_secs(60)));
        assert!(rl.check("1.2.3.4").await, "1st allowed");
        assert!(rl.check("1.2.3.4").await, "2nd allowed");
        assert!(!rl.check("1.2.3.4").await, "3rd denied");
        // A different client has its own budget.
        assert!(rl.check("9.9.9.9").await, "other client allowed");
    }

    #[tokio::test]
    async fn memory_window_resets() {
        let rl = RateLimiter::new(cfg(1, Duration::from_millis(40)));
        assert!(rl.check("k").await);
        assert!(!rl.check("k").await, "denied within window");
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(rl.check("k").await, "allowed after window rolls over");
    }

    /// Two `RateLimiter`s over one database stand in for two app instances. The
    /// limit must be the *combined* count, not per-node. Opt-in: set
    /// `CACHE_TEST_DATABASE_URL` to run.
    #[tokio::test]
    async fn postgres_limit_is_shared_across_instances() {
        let Some(url) = std::env::var("CACHE_TEST_DATABASE_URL").ok() else {
            eprintln!("CACHE_TEST_DATABASE_URL not set — skipping shared rate-limit test");
            return;
        };
        let pool = sqlx::PgPool::connect(&url).await.expect("connect");
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS rate_limit_bucket (\
                scope text NOT NULL, client_key text NOT NULL, window_start bigint NOT NULL, \
                count integer NOT NULL DEFAULT 0, PRIMARY KEY (scope, client_key, window_start))",
        )
        .execute(&pool)
        .await
        .expect("ensure table");
        sqlx::query("DELETE FROM rate_limit_bucket WHERE scope = 'rl_xproc_test'")
            .execute(&pool)
            .await
            .ok();

        // max 3 per window, two "nodes" sharing the DB.
        let node_a = RateLimiter::postgres(cfg(3, Duration::from_secs(60)), pool.clone(), "rl_xproc_test");
        let node_b = RateLimiter::postgres(cfg(3, Duration::from_secs(60)), pool.clone(), "rl_xproc_test");
        let key = "203.0.113.7";

        assert!(node_a.check(key).await, "req1 on A allowed (count 1)");
        assert!(node_b.check(key).await, "req2 on B allowed (count 2)");
        assert!(node_a.check(key).await, "req3 on A allowed (count 3)");
        assert!(!node_b.check(key).await, "req4 on B denied — combined limit reached");
        assert!(!node_a.check(key).await, "req5 on A also denied");

        sqlx::query("DELETE FROM rate_limit_bucket WHERE scope = 'rl_xproc_test'")
            .execute(&pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn postgres_strict_fails_closed_on_bad_pool() {
        // A pool pointed at a non-existent server errors on every query; the
        // strict limiter must reject (false), the lenient one must allow (true).
        let bad = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("postgres://nouser:nopass@127.0.0.1:1/nodb")
            .expect("lazy pool builds without connecting");
        let strict = RateLimiter::postgres_strict(cfg(5, Duration::from_secs(60)), bad.clone(), "s");
        let lenient = RateLimiter::postgres(cfg(5, Duration::from_secs(60)), bad, "s");
        assert!(!strict.check("k").await, "strict fails closed → deny");
        assert!(lenient.check("k").await, "lenient fails open → allow");
    }
}
