//! # Mobile / programmatic auth — access + refresh tokens
//!
//! Backs the host's `/api/v1/auth/*` surface for first-party apps such as the
//! SESB field-technician app. A username+password login mints:
//!
//! - a short-lived **access token** — sent as `Authorization: Bearer` on every
//!   API call; resolves to the owning user with their roles (same Cedar gates
//!   as the UI);
//! - a long-lived **refresh token** — used only to mint the next access token
//!   when connectivity returns. This is the property the offline field flow
//!   needs: the device works offline against its local queue, and only *sync*
//!   needs a live token.
//!
//! Design (see migration `132_mobile_auth`):
//!
//! - **Opaque + DB-backed.** Only the SHA-256 hash is stored (the `sessions` /
//!   `api_tokens` scheme). A lost device is killed with one `UPDATE` — no JWT
//!   blocklist. This is the zero-trust instant-revocation property.
//! - **Family = device login.** Both rows of a pair share a `family_id`.
//!   Rotation issues new rows in the same family; logout / device-revoke /
//!   reuse-detection revoke the whole family.
//! - **Refresh rotation with reuse detection.** Each refresh is single-use
//!   (`consumed_at`). Presenting an already-consumed refresh means the token
//!   leaked and both the thief and the honest client are racing — so the
//!   family is revoked and everyone must re-login. Standard OAuth refresh
//!   rotation semantics.
//!
//! The host wires authentication, rate-limiting, tenant selection, and audit
//! around these primitives — see `vortex-cli`'s `auth_*` handlers.

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Access-token secret prefix — recognisable in logs/proxies without being
/// usable, and distinct from `api_tokens` (`vtx_`) so the two never collide.
pub const ACCESS_PREFIX: &str = "vtxa_";
/// Refresh-token secret prefix.
pub const REFRESH_PREFIX: &str = "vtxr_";

/// SHA-256 hex of a presented secret — the value stored in `token_hash`.
/// Reuses the exact scheme of [`crate::api::hash_secret`].
pub fn hash_secret(secret: &str) -> String {
    crate::api::hash_secret(secret)
}

/// Mint a fresh secret with `prefix`. Returns `(secret, hash)`; the secret is
/// returned once to the client and never stored. Entropy comes from
/// `vortex_security::crypto` (ring's `SystemRandom`), like `api::mint_secret`.
fn mint(prefix: &str) -> Result<(String, String), String> {
    let raw =
        vortex_security::crypto::generate_key_base64().map_err(|_| "rng failure".to_string())?;
    let body: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let secret = format!("{prefix}{body}");
    let hash = hash_secret(&secret);
    Ok((secret, hash))
}

/// A freshly issued access+refresh pair. The secrets are plaintext, shown to
/// the client once.
#[derive(Debug, Clone)]
pub struct IssuedPair {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
    pub family_id: Uuid,
}

/// Context for a login/rotation: who, which device, what scopes, how long, and
/// the request fingerprint for the audit columns.
#[derive(Debug, Clone)]
pub struct IssueCtx<'a> {
    pub user_id: Uuid,
    pub device_id: Option<&'a str>,
    pub device_name: Option<&'a str>,
    pub scopes: &'a [String],
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// An access token successfully resolved against a live, non-expired row whose
/// owning user is active and unlocked.
#[derive(Debug, Clone)]
pub struct ResolvedMobile {
    pub token_id: Uuid,
    pub family_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub full_name: Option<String>,
    pub roles: Vec<String>,
    pub scopes: Vec<String>,
    pub device_id: Option<String>,
}

impl ResolvedMobile {
    /// Coarse capability gate — mirrors [`crate::api::ResolvedToken::can_write`].
    pub fn can_write(&self) -> bool {
        self.scopes.iter().any(|s| s == "write")
    }
}

/// Why a refresh failed. The handler maps these to distinct client-facing
/// codes so the app can tell "just log in again" (`Expired`) apart from
/// "your session was compromised" (`Reused`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshError {
    /// Unknown / malformed / revoked token, or disabled user. No oracle.
    Invalid,
    /// The refresh token was valid but past its lifetime — re-login required.
    Expired,
    /// A consumed (already-rotated) refresh was presented again — the family
    /// has been revoked as a theft signal.
    Reused,
}

async fn fetch_roles(db: &PgPool, user_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .unwrap_or_default()
}

/// Issue a fresh access+refresh pair in a **new family** (a device login).
/// Both rows are inserted in one transaction.
pub async fn issue_pair(db: &PgPool, ctx: &IssueCtx<'_>) -> Result<IssuedPair, String> {
    issue_in_family(db, ctx, Uuid::new_v4(), None).await
}

/// Issue a pair into `family_id`. `parent` links the new refresh to the one it
/// replaces (rotation lineage); `None` on a fresh login.
async fn issue_in_family(
    db: &PgPool,
    ctx: &IssueCtx<'_>,
    family_id: Uuid,
    parent: Option<Uuid>,
) -> Result<IssuedPair, String> {
    let now = Utc::now();
    let access_exp = now + ctx.access_ttl;
    let refresh_exp = now + ctx.refresh_ttl;
    let (access_secret, access_hash) = mint(ACCESS_PREFIX)?;
    let (refresh_secret, refresh_hash) = mint(REFRESH_PREFIX)?;

    let mut tx = db.begin().await.map_err(|e| e.to_string())?;

    // Refresh row first so the access row can reference it as parent.
    // `$9::inet` casts the text-bound IP to the INET column.
    let refresh_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO mobile_auth_token
            (family_id, kind, token_hash, user_id, device_id, device_name,
             scopes, parent_id, expires_at, ip_address, user_agent)
        VALUES ($1, 'refresh', $2, $3, $4, $5, $6, $7, $8, $9::inet, $10)
        RETURNING id
        "#,
    )
    .bind(family_id)
    .bind(&refresh_hash)
    .bind(ctx.user_id)
    .bind(ctx.device_id)
    .bind(ctx.device_name)
    .bind(ctx.scopes)
    .bind(parent)
    .bind(refresh_exp)
    .bind(ctx.ip)
    .bind(ctx.user_agent)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    sqlx::query(
        r#"
        INSERT INTO mobile_auth_token
            (family_id, kind, token_hash, user_id, device_id, device_name,
             scopes, parent_id, expires_at, ip_address, user_agent)
        VALUES ($1, 'access', $2, $3, $4, $5, $6, $7, $8, $9::inet, $10)
        "#,
    )
    .bind(family_id)
    .bind(&access_hash)
    .bind(ctx.user_id)
    .bind(ctx.device_id)
    .bind(ctx.device_name)
    .bind(ctx.scopes)
    .bind(refresh_id)
    .bind(access_exp)
    .bind(ctx.ip)
    .bind(ctx.user_agent)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    tx.commit().await.map_err(|e| e.to_string())?;

    Ok(IssuedPair {
        access_token: access_secret,
        refresh_token: refresh_secret,
        access_expires_at: access_exp,
        refresh_expires_at: refresh_exp,
        family_id,
    })
}

/// Resolve a presented **access** secret to its owner. Returns `None` for any
/// failure mode — unknown hash, revoked, expired, wrong kind, or a
/// disabled/locked user — so the caller cannot distinguish them (no oracle).
pub async fn resolve_access(db: &PgPool, secret: &str) -> Option<ResolvedMobile> {
    if !secret.starts_with(ACCESS_PREFIX) {
        return None;
    }
    let hash = hash_secret(secret);
    let row = sqlx::query(
        r#"
        SELECT t.id AS token_id, t.family_id, t.user_id, t.scopes, t.device_id,
               u.username, u.full_name, u.active, u.locked
        FROM mobile_auth_token t
        JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = $1
          AND t.kind = 'access'
          AND NOT t.revoked
          AND t.expires_at > NOW()
        "#,
    )
    .bind(&hash)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;

    if !row.get::<bool, _>("active") || row.get::<bool, _>("locked") {
        return None;
    }
    let user_id: Uuid = row.get("user_id");
    let roles = fetch_roles(db, user_id).await;

    Some(ResolvedMobile {
        token_id: row.get("token_id"),
        family_id: row.get("family_id"),
        user_id,
        username: row.get("username"),
        full_name: row.try_get("full_name").ok().flatten(),
        roles,
        scopes: row.try_get("scopes").unwrap_or_default(),
        device_id: row.try_get("device_id").ok().flatten(),
    })
}

/// Best-effort `last_used_at` stamp. Non-fatal — telemetry, not auth.
pub async fn touch_last_used(db: &PgPool, token_id: Uuid) {
    let _ = sqlx::query("UPDATE mobile_auth_token SET last_used_at = NOW() WHERE id = $1")
        .bind(token_id)
        .execute(db)
        .await;
}

/// Rotate a **refresh** secret: validate it, consume it, and issue a fresh
/// pair in the same family. On reuse (a consumed refresh presented again) the
/// whole family is revoked and [`RefreshError::Reused`] is returned.
///
/// The lookup + consume run in a transaction with `FOR UPDATE` so two racing
/// refreshes can't both succeed.
pub async fn rotate_refresh(
    db: &PgPool,
    secret: &str,
    access_ttl: Duration,
    refresh_ttl: Duration,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<IssuedPair, RefreshError> {
    if !secret.starts_with(REFRESH_PREFIX) {
        return Err(RefreshError::Invalid);
    }
    let hash = hash_secret(secret);

    let mut tx = db.begin().await.map_err(|_| RefreshError::Invalid)?;

    let row = sqlx::query(
        r#"
        SELECT t.id, t.family_id, t.user_id, t.device_id, t.device_name,
               t.scopes, t.consumed_at, t.revoked, t.expires_at,
               u.active, u.locked
        FROM mobile_auth_token t
        JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = $1 AND t.kind = 'refresh'
        FOR UPDATE OF t
        "#,
    )
    .bind(&hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("mobile rotate: select failed: {e}");
        RefreshError::Invalid
    })?;

    let Some(row) = row else {
        // Normal invalid-token path (unknown/mistyped secret) — not an error.
        return Err(RefreshError::Invalid);
    };

    let family_id: Uuid = row.get("family_id");
    let revoked: bool = row.get("revoked");
    let consumed_at: Option<DateTime<Utc>> = row.try_get("consumed_at").ok().flatten();
    let expires_at: DateTime<Utc> = row.get("expires_at");

    // Reuse detection: a consumed (or already-revoked-but-consumed) refresh
    // presented again means the secret leaked. Burn the whole family.
    if consumed_at.is_some() {
        let _ = sqlx::query(
            "UPDATE mobile_auth_token SET revoked = true, revoked_at = NOW(), \
             revoked_reason = 'refresh_reuse_detected' \
             WHERE family_id = $1 AND NOT revoked",
        )
        .bind(family_id)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
        return Err(RefreshError::Reused);
    }
    if revoked {
        return Err(RefreshError::Invalid);
    }
    if !row.get::<bool, _>("active") || row.get::<bool, _>("locked") {
        return Err(RefreshError::Invalid);
    }
    if expires_at <= Utc::now() {
        return Err(RefreshError::Expired);
    }

    // Consume this refresh and revoke the family's current access token(s);
    // the caller's old access token dies at rotation, new one is issued below.
    let this_id: Uuid = row.get("id");
    sqlx::query("UPDATE mobile_auth_token SET consumed_at = NOW() WHERE id = $1")
        .bind(this_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| RefreshError::Invalid)?;
    sqlx::query(
        "UPDATE mobile_auth_token SET revoked = true, revoked_at = NOW(), \
         revoked_reason = 'rotated' \
         WHERE family_id = $1 AND kind = 'access' AND NOT revoked",
    )
    .bind(family_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| RefreshError::Invalid)?;

    tx.commit().await.map_err(|_| RefreshError::Invalid)?;

    let user_id: Uuid = row.get("user_id");
    let device_id: Option<String> = row.try_get("device_id").ok().flatten();
    let device_name: Option<String> = row.try_get("device_name").ok().flatten();
    let scopes: Vec<String> = row.try_get("scopes").unwrap_or_default();

    issue_in_family(
        db,
        &IssueCtx {
            user_id,
            device_id: device_id.as_deref(),
            device_name: device_name.as_deref(),
            scopes: &scopes,
            access_ttl,
            refresh_ttl,
            ip,
            user_agent,
        },
        family_id,
        Some(this_id),
    )
    .await
    .map_err(|e| {
        tracing::error!("mobile rotate: issue_in_family failed: {e}");
        RefreshError::Invalid
    })
}

/// Revoke every live token in a family (logout of one device session).
pub async fn revoke_family(db: &PgPool, family_id: Uuid, reason: &str) {
    let _ = sqlx::query(
        "UPDATE mobile_auth_token SET revoked = true, revoked_at = NOW(), revoked_reason = $2 \
         WHERE family_id = $1 AND NOT revoked",
    )
    .bind(family_id)
    .bind(reason)
    .execute(db)
    .await;
}

/// Logout: revoke the family of the presented secret (access **or** refresh).
/// Returns true if a matching live token was found.
pub async fn revoke_by_secret(db: &PgPool, secret: &str, reason: &str) -> bool {
    let hash = hash_secret(secret);
    let family: Option<Uuid> =
        sqlx::query_scalar("SELECT family_id FROM mobile_auth_token WHERE token_hash = $1")
            .bind(&hash)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    if let Some(family_id) = family {
        revoke_family(db, family_id, reason).await;
        true
    } else {
        false
    }
}

/// One active device/session for the "your devices" listing.
#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub family_id: Uuid,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Active device sessions for a user — one row per live (non-revoked,
/// non-expired) refresh token, most recently used first.
pub async fn list_devices(db: &PgPool, user_id: Uuid) -> Vec<DeviceRow> {
    let rows = sqlx::query(
        r#"
        SELECT family_id, device_id, device_name, last_used_at, created_at, expires_at
        FROM mobile_auth_token
        WHERE user_id = $1 AND kind = 'refresh'
          AND NOT revoked AND expires_at > NOW() AND consumed_at IS NULL
        ORDER BY COALESCE(last_used_at, created_at) DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.iter()
        .map(|r| DeviceRow {
            family_id: r.get("family_id"),
            device_id: r.try_get("device_id").ok().flatten(),
            device_name: r.try_get("device_name").ok().flatten(),
            last_used_at: r.try_get("last_used_at").ok().flatten(),
            created_at: r.get("created_at"),
            expires_at: r.get("expires_at"),
        })
        .collect()
}

/// Revoke a device by `family_id`, but only if it belongs to `user_id` (so a
/// user can only revoke their own devices). Returns rows affected.
pub async fn revoke_device(db: &PgPool, user_id: Uuid, family_id: Uuid, reason: &str) -> u64 {
    sqlx::query(
        "UPDATE mobile_auth_token SET revoked = true, revoked_at = NOW(), revoked_reason = $3 \
         WHERE family_id = $1 AND user_id = $2 AND NOT revoked",
    )
    .bind(family_id)
    .bind(user_id)
    .bind(reason)
    .execute(db)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0)
}
