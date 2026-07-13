//! # Public REST API — tokens and generic record access
//!
//! This module backs the host's `/api/v1` surface. It has two halves:
//!
//! 1. **Token store** (`api_tokens`): mint / resolve / list / revoke bearer
//!    credentials. A token authenticates *as a user* — the resolved
//!    [`ResolvedToken`] carries that user's roles, so the same Cedar policy
//!    gates that protect the UI protect the API. The raw secret is shown
//!    once and never stored; only its SHA-256 hash is kept (the exact scheme
//!    `sessions` uses).
//!
//! 2. **Generic record access**: list / get / create / update / delete rows
//!    of any model registered in `ir_model` / `ir_model_field`. Every table
//!    and column name is allow-listed against that registry and validated as
//!    a SQL identifier before it reaches a query; every value is bound as a
//!    parameter. Rows are emitted as JSON via Postgres `jsonb_build_object`
//!    over the registered fields, so unregistered columns never leak.
//!
//! The host wires authentication (Bearer + tenant header), policy checks, and
//! audit logging around these primitives — see `vortex-cli`'s `api_*`
//! handlers. Keeping the SQL here means the safety-critical query building is
//! unit-testable in one place and reused verbatim by every endpoint.

use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

// ─── Identifier safety ────────────────────────────────────────────────────

/// A conservative SQL-identifier check: non-empty, ≤63 chars, ASCII
/// alphanumeric or underscore only. Mirrors `user_reports::ident` so the two
/// safe-SQL layers agree on what a legal table/column name looks like.
pub(crate) fn ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ─── Token store ──────────────────────────────────────────────────────────

/// The full plaintext secret a client presents (e.g. `vtx_…`), returned only
/// at creation time alongside the persisted row.
pub const TOKEN_PREFIX: &str = "vtx_";

/// SHA-256 hex of a presented secret — the value stored in `token_hash`.
pub fn hash_secret(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    hex::encode(h.finalize())
}

/// Mint a fresh secret. Returns `(secret, display_prefix, hash)`:
/// - `secret` is shown to the operator once and never stored,
/// - `display_prefix` is a recognisable leading slice kept for the UI,
/// - `hash` is what goes in `api_tokens.token_hash`.
///
/// Entropy comes from `vortex_security::crypto` (ring's `SystemRandom`), so
/// no extra RNG dependency is pulled into the framework. The base64 secret is
/// reduced to URL/header-safe alphanumerics.
pub fn mint_secret() -> Result<(String, String, String), String> {
    let raw = vortex_security::crypto::generate_key_base64()
        .map_err(|_| "rng failure".to_string())?;
    let body: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let secret = format!("{TOKEN_PREFIX}{body}");
    // 12-char display prefix: 'vtx_' + 8 secret chars.
    let prefix: String = secret.chars().take(12).collect();
    let hash = hash_secret(&secret);
    Ok((secret, prefix, hash))
}

/// A token successfully resolved against a live, non-expired row whose owning
/// user is active and unlocked.
#[derive(Debug, Clone)]
pub struct ResolvedToken {
    pub token_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub full_name: Option<String>,
    pub roles: Vec<String>,
    pub scopes: Vec<String>,
}

impl ResolvedToken {
    /// Coarse capability gate. An empty scope set is read-only; `write`
    /// permits mutation endpoints. Policy still applies on top.
    pub fn can_write(&self) -> bool {
        self.scopes.iter().any(|s| s == "write")
    }
}

/// Resolve a presented secret to its owner. Returns `None` for any failure
/// mode — unknown hash, revoked, expired, or a disabled/locked user — so the
/// caller cannot distinguish them (no oracle).
pub async fn resolve_token(db: &PgPool, secret: &str) -> Option<ResolvedToken> {
    let hash = hash_secret(secret);
    let row = sqlx::query(
        r#"
        SELECT t.id            AS token_id,
               t.user_id       AS user_id,
               t.scopes        AS scopes,
               u.username      AS username,
               u.full_name     AS full_name,
               u.active        AS active,
               u.locked        AS locked
        FROM api_tokens t
        JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = $1
          AND NOT t.revoked
          AND (t.expires_at IS NULL OR t.expires_at > NOW())
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
    let token_id: Uuid = row.get("token_id");
    let user_id: Uuid = row.get("user_id");
    let scopes: Vec<String> = row.try_get("scopes").unwrap_or_default();

    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    Some(ResolvedToken {
        token_id,
        user_id,
        username: row.get("username"),
        full_name: row.try_get("full_name").ok().flatten(),
        roles,
        scopes,
    })
}

/// Best-effort `last_used_at` stamp. Failure is non-fatal — telemetry, not auth.
pub async fn touch_last_used(db: &PgPool, token_id: Uuid) {
    let _ = sqlx::query("UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1")
        .bind(token_id)
        .execute(db)
        .await;
}

/// One row for the admin listing (never includes the secret or its hash).
#[derive(Debug, Clone)]
pub struct TokenRow {
    pub id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub username: String,
    pub scopes: Vec<String>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// List tokens (most recent first) for the admin UI.
pub async fn list_tokens(db: &PgPool) -> Vec<TokenRow> {
    let rows = sqlx::query(
        r#"
        SELECT t.id, t.name, t.token_prefix, t.scopes, t.last_used_at,
               t.expires_at, t.revoked, t.created_at, u.username
        FROM api_tokens t
        JOIN users u ON u.id = t.user_id
        ORDER BY t.created_at DESC
        "#,
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.iter()
        .map(|r| TokenRow {
            id: r.get("id"),
            name: r.get("name"),
            token_prefix: r.get("token_prefix"),
            username: r.get("username"),
            scopes: r.try_get("scopes").unwrap_or_default(),
            last_used_at: r.try_get("last_used_at").ok().flatten(),
            expires_at: r.try_get("expires_at").ok().flatten(),
            revoked: r.get("revoked"),
            created_at: r.get("created_at"),
        })
        .collect()
}

/// Mint and persist a token for `user_id`. Returns the one-time secret.
pub async fn create_token(
    db: &PgPool,
    name: &str,
    user_id: Uuid,
    scopes: &[String],
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    created_by: Option<Uuid>,
) -> Result<String, String> {
    let (secret, prefix, hash) = mint_secret()?;
    sqlx::query(
        r#"
        INSERT INTO api_tokens (name, token_prefix, token_hash, user_id, scopes, expires_at, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(name)
    .bind(&prefix)
    .bind(&hash)
    .bind(user_id)
    .bind(scopes)
    .bind(expires_at)
    .bind(created_by)
    .execute(db)
    .await
    .map_err(|e| format!("insert failed: {e}"))?;
    Ok(secret)
}

/// Revoke a token (idempotent). Revoked tokens stay in the table for audit.
pub async fn revoke_token(db: &PgPool, id: Uuid) -> Result<(), String> {
    sqlx::query("UPDATE api_tokens SET revoked = true, revoked_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(|e| format!("revoke failed: {e}"))?;
    Ok(())
}

// ─── Model registry introspection ─────────────────────────────────────────

/// Resolve a model name to its physical table, requiring the model be active
/// and the table a legal identifier.
async fn model_table(db: &PgPool, model: &str) -> Option<String> {
    let table: Option<String> =
        sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1 AND is_active = true")
            .bind(model)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    table.filter(|t| ident(t))
}

/// Registered field *names* for a model, in declared order. These drive the
/// read projection — reads expose exactly the registered fields, no more.
/// Filtered to legal identifiers so a malformed registry row can never reach a
/// query.
async fn model_fields(db: &PgPool, model: &str) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT f.name FROM ir_model_field f \
         JOIN ir_model m ON m.id = f.model_id \
         WHERE m.name = $1 ORDER BY f.sequence, f.name",
    )
    .bind(model)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.iter()
        .map(|r| r.get::<String, _>("name"))
        .filter(|n| ident(n))
        .collect()
}

/// Columns the API will never let a client write (identity, audit, bookkeeping).
fn is_protected_column(col: &str) -> bool {
    matches!(col, "id" | "created_at" | "updated_at" | "created_by")
}

/// The real, writable columns of a table: `column_name -> udt_name`, with
/// protected and generated columns removed. This — not the display registry
/// (`ir_model_field`) — is the write allow-list, so a client can set any
/// genuine column (e.g. a required `company_id`) while typos and injected
/// names are still rejected. The DB enforces NOT NULL / FK / check constraints
/// on top. `udt_name` (e.g. `uuid`, `int8`, `numeric`, `jsonb`) is a valid
/// cast target, used to coerce the bound JSON value to the column's type.
async fn writable_columns(db: &PgPool, table: &str) -> std::collections::HashMap<String, String> {
    let mut cols = table_columns(db, table).await;
    cols.retain(|c, _| !is_protected_column(c));
    cols
}

/// Every real (non-generated) column of a table with a legal identifier,
/// `column_name -> udt_name` — including the identity/audit columns the
/// write allow-list strips. The duplication primitive uses this to copy
/// full rows while handling identity columns itself.
pub(crate) async fn table_columns(
    db: &PgPool,
    table: &str,
) -> std::collections::HashMap<String, String> {
    let rows = sqlx::query(
        "SELECT column_name, udt_name FROM information_schema.columns \
         WHERE table_name = $1 AND is_generated = 'NEVER'",
    )
    .bind(table)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.iter()
        .map(|r| (r.get::<String, _>("column_name"), r.get::<String, _>("udt_name")))
        .filter(|(c, udt)| ident(c) && ident(udt))
        .collect()
}

// ─── Generic record access ────────────────────────────────────────────────

/// Build a `jsonb_build_object('field', t.field, …)` projection over the
/// registered fields, always including `id`. Field names are pre-validated.
fn json_projection(fields: &[String]) -> String {
    let mut parts: Vec<String> = vec!["'id', t.id".to_string()];
    for f in fields {
        if f == "id" {
            continue;
        }
        parts.push(format!("'{0}', t.{0}", f));
    }
    format!("jsonb_build_object({})", parts.join(", "))
}

/// Outcome of a list query: the page of records plus paging echo.
pub struct RecordPage {
    pub records: Vec<Value>,
    pub limit: i64,
    pub offset: i64,
}

/// List records of `model`. `filters` are `(field, value)` equality pairs;
/// each field must be registered. `limit` is clamped to [1, 200].
pub async fn list_records(
    db: &PgPool,
    model: &str,
    filters: &[(String, String)],
    limit: i64,
    offset: i64,
) -> Result<RecordPage, String> {
    let table = model_table(db, model).await.ok_or("unknown model")?;
    let fields = model_fields(db, model).await;
    if fields.is_empty() {
        return Err("model has no registered fields".into());
    }
    let known: std::collections::HashSet<&str> = fields.iter().map(|f| f.as_str()).collect();

    let mut where_parts: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    for (field, value) in filters {
        if field == "id" {
            where_parts.push(format!("t.id::text = ${}", binds.len() + 1));
            binds.push(value.clone());
            continue;
        }
        if !ident(field) || !known.contains(field.as_str()) {
            return Err(format!("unknown filter field '{field}'"));
        }
        where_parts.push(format!("t.{}::text = ${}", field, binds.len() + 1));
        binds.push(value.clone());
    }
    let where_sql = if where_parts.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_parts.join(" AND "))
    };

    let limit = limit.clamp(1, 200);
    let offset = offset.max(0);
    let sql = format!(
        "SELECT {proj} FROM {table} t{where_sql} ORDER BY t.id LIMIT {limit} OFFSET {offset}",
        proj = json_projection(&fields),
    );
    let mut q = sqlx::query_scalar::<_, Value>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let records = q.fetch_all(db).await.map_err(|e| format!("query failed: {e}"))?;
    Ok(RecordPage { records, limit, offset })
}

/// Fetch one record by id, or `None` if absent.
pub async fn get_record(db: &PgPool, model: &str, id: Uuid) -> Result<Option<Value>, String> {
    let table = model_table(db, model).await.ok_or("unknown model")?;
    let fields = model_fields(db, model).await;
    if fields.is_empty() {
        return Err("model has no registered fields".into());
    }
    let sql = format!(
        "SELECT {proj} FROM {table} t WHERE t.id = $1",
        proj = json_projection(&fields),
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(|e| format!("query failed: {e}"))
}

/// Restrict an input object to writable, real columns. Returns the
/// `(column, udt_cast)` pairs to assign and the filtered jsonb to bind as `$1`.
/// Identity/audit columns are silently dropped; unknown columns are rejected;
/// errors if nothing usable remains.
fn writable_assignments(
    columns: &std::collections::HashMap<String, String>,
    body: &Value,
) -> Result<(Vec<(String, String)>, Value), String> {
    let obj = body.as_object().ok_or("body must be a JSON object")?;
    let mut cols: Vec<(String, String)> = Vec::new();
    let mut filtered = serde_json::Map::new();
    for (k, v) in obj {
        if is_protected_column(k) {
            continue; // silently ignore identity/audit columns
        }
        let Some(udt) = columns.get(k.as_str()) else {
            return Err(format!("unknown field '{k}'"));
        };
        cols.push((k.clone(), udt.clone()));
        filtered.insert(k.clone(), v.clone());
    }
    if cols.is_empty() {
        return Err("no writable fields in body".into());
    }
    Ok((cols, Value::Object(filtered)))
}

/// Build the `($1->>'col')::udt` value expression for one column (or
/// `($1->'col')::jsonb` for JSON columns, which must keep their structure).
fn value_expr(col: &str, udt: &str) -> String {
    if udt == "jsonb" || udt == "json" {
        format!("($1->'{col}')::{udt}")
    } else {
        format!("($1->>'{col}')::{udt}")
    }
}

/// Create a record from a JSON body. Unspecified columns take their DB
/// defaults; identity/audit columns are ignored if supplied. Returns the new id.
pub async fn create_record(db: &PgPool, model: &str, body: &Value) -> Result<Uuid, String> {
    let table = model_table(db, model).await.ok_or("unknown model")?;
    let columns = writable_columns(db, &table).await;
    let (cols, filtered) = writable_assignments(&columns, body)?;

    // Each value is extracted from the single bound jsonb param ($1) and cast
    // to its real column type. Unspecified columns take their DB defaults.
    let col_list = cols.iter().map(|(c, _)| c.clone()).collect::<Vec<_>>().join(", ");
    let val_list = cols
        .iter()
        .map(|(c, udt)| value_expr(c, udt))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("INSERT INTO {table} ({col_list}) VALUES ({val_list}) RETURNING id");
    let id: Uuid = sqlx::query_scalar(&sql)
        .bind(&filtered)
        .fetch_one(db)
        .await
        .map_err(|e| format!("insert failed: {e}"))?;
    Ok(id)
}

/// Duplicate a record of `model` into a fresh row: id/timestamps are
/// regenerated, `created_by` stamped, everything else copied verbatim.
/// Modules with richer needs (sequence numbers, line tables, lifecycle
/// resets) build a [`crate::duplicate::DuplicateSpec`] directly; this is
/// the generic surface behind `POST /api/v1/{model}/{id}/duplicate`.
pub async fn duplicate_record(
    db: &PgPool,
    model: &str,
    id: Uuid,
    created_by: Option<Uuid>,
) -> Result<Uuid, String> {
    let table = model_table(db, model).await.ok_or("unknown model")?;
    crate::duplicate::DuplicateSpec::new(&table).execute(db, id, created_by).await
}

/// Update a record by id. Only registered, non-protected fields present in the
/// body are written; `updated_at` is bumped when the column exists. Returns
/// whether a row matched.
pub async fn update_record(db: &PgPool, model: &str, id: Uuid, body: &Value) -> Result<bool, String> {
    let table = model_table(db, model).await.ok_or("unknown model")?;
    let columns = writable_columns(db, &table).await;
    let (cols, filtered) = writable_assignments(&columns, body)?;

    let mut sets: Vec<String> = cols
        .iter()
        .map(|(c, udt)| format!("{c} = {}", value_expr(c, udt)))
        .collect();
    if column_exists(db, &table, "updated_at").await {
        sets.push("updated_at = NOW()".to_string());
    }
    let sql = format!("UPDATE {table} SET {} WHERE id = $2", sets.join(", "));
    let res = sqlx::query(&sql)
        .bind(&filtered)
        .bind(id)
        .execute(db)
        .await
        .map_err(|e| format!("update failed: {e}"))?;
    Ok(res.rows_affected() > 0)
}

/// Delete a record by id. Returns whether a row matched.
pub async fn delete_record(db: &PgPool, model: &str, id: Uuid) -> Result<bool, String> {
    let table = model_table(db, model).await.ok_or("unknown model")?;
    let sql = format!("DELETE FROM {table} WHERE id = $1");
    let res = sqlx::query(&sql)
        .bind(id)
        .execute(db)
        .await
        .map_err(|e| format!("delete failed: {e}"))?;
    Ok(res.rows_affected() > 0)
}

/// Cheap existence check for a column, used to decide whether to bump
/// `updated_at`. The table name is already validated; the column is a literal.
async fn column_exists(db: &PgPool, table: &str, col: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM information_schema.columns \
         WHERE table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(col)
    .fetch_one(db)
    .await
    .map(|n| n > 0)
    .unwrap_or(false)
}

/// List registered models (name, display name, table) for `GET /api/v1/models`.
pub async fn list_models(db: &PgPool) -> Vec<Value> {
    let rows = sqlx::query(
        "SELECT name, display_name, table_name, module FROM ir_model \
         WHERE is_active = true ORDER BY name",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.iter()
        .map(|r| {
            json!({
                "name": r.get::<String, _>("name"),
                "display_name": r.get::<String, _>("display_name"),
                "table": r.get::<String, _>("table_name"),
                "module": r.try_get::<Option<String>, _>("module").ok().flatten(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_rejects_injection() {
        assert!(ident("contacts"));
        assert!(ident("record_state"));
        assert!(!ident("name; DROP TABLE users"));
        assert!(!ident("a-b"));
        assert!(!ident(""));
        assert!(!ident(&"x".repeat(64)));
    }

    #[test]
    fn hash_is_stable_and_hex() {
        let h = hash_secret("vtx_abc");
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_secret("vtx_abc"));
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn mint_produces_prefixed_secret_and_matching_hash() {
        let (secret, prefix, hash) = mint_secret().unwrap();
        assert!(secret.starts_with(TOKEN_PREFIX));
        assert!(secret.starts_with(&prefix));
        assert_eq!(prefix.len(), 12);
        assert_eq!(hash, hash_secret(&secret));
    }

    #[test]
    fn value_expr_handles_json_vs_scalar() {
        assert_eq!(value_expr("data", "jsonb"), "($1->'data')::jsonb");
        assert_eq!(value_expr("n", "int8"), "($1->>'n')::int8");
        assert_eq!(value_expr("cid", "uuid"), "($1->>'cid')::uuid");
    }

    #[test]
    fn protected_columns_are_blocked() {
        assert!(is_protected_column("id"));
        assert!(is_protected_column("created_at"));
        assert!(!is_protected_column("name"));
    }

    #[test]
    fn projection_always_includes_id_once() {
        let fields = vec!["id".to_string(), "name".to_string()];
        let p = json_projection(&fields);
        assert_eq!(p.matches("'id'").count(), 1);
        assert!(p.contains("'name', t.name"));
    }

    #[test]
    fn writable_filters_protected_and_unknown() {
        let cols: std::collections::HashMap<String, String> = [
            ("name".to_string(), "varchar".to_string()),
            ("company_id".to_string(), "uuid".to_string()),
        ]
        .into_iter()
        .collect();
        // protected id ignored, real columns kept
        let body = json!({"id": "x", "name": "Acme", "company_id": "00000000-0000-0000-0000-000000000001"});
        let (assigned, filtered) = writable_assignments(&cols, &body).unwrap();
        assert_eq!(assigned.len(), 2);
        assert!(filtered.get("id").is_none());
        assert!(filtered.get("company_id").is_some());
        // unknown column rejected
        assert!(writable_assignments(&cols, &json!({"bogus": 1})).is_err());
        // empty after filtering protected-only body rejected
        assert!(writable_assignments(&cols, &json!({"id": "x"})).is_err());
    }

    #[test]
    fn scopes_gate_writes() {
        let mk = |scopes: Vec<String>| ResolvedToken {
            token_id: Uuid::nil(),
            user_id: Uuid::nil(),
            username: "u".into(),
            full_name: None,
            roles: vec![],
            scopes,
        };
        assert!(!mk(vec![]).can_write());
        assert!(mk(vec!["write".into()]).can_write());
    }
}
