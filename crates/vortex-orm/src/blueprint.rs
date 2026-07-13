//! Blueprint schema mechanics — the runtime DDL service.
//!
//! A *Blueprint* is a user-defined, governed model created from the browser
//! with no deploy (see `docs/BLUEPRINTS_DESIGN.md`). Its records live in a real
//! generated table (`x_<name>`, one real column per field) so the entire
//! generic view layer, REST API, webhooks, and automation — all of which read
//! the `ir_model` registry — work on it unchanged.
//!
//! This module is the **only** place that composes and executes runtime DDL,
//! and it is deliberately security-critical: it is the first `CREATE TABLE` /
//! `ALTER TABLE`-at-runtime path in the codebase. The discipline is:
//!
//! 1. The caller never supplies SQL — only validated metadata.
//! 2. Every identifier interpolated into a statement first passes
//!    [`validate_identifier`] (strict pattern + reserved-word blocklist), and
//!    every generated **table** additionally carries the `x_` namespace prefix.
//! 3. Column types come from a fixed vocabulary ([`column_type`]).
//! 4. Every executed statement is appended to `blueprint_ddl_log` in the same
//!    transaction, so a tenant's generated schema stays reproducible.
//!
//! Governance (Cedar policy checks + WORM audit + version bookkeeping) lives one
//! layer up in `vortex-framework`; this module has no audit/policy dependency.

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Errors from the DDL service. Anything that isn't a clean, validated
/// operation fails loud — nothing is silently skipped.
#[derive(Debug, thiserror::Error)]
pub enum BlueprintError {
    /// Identifier failed the strict pattern (length, charset, leading char) or
    /// a generated table lacked the required `x_` prefix.
    #[error("invalid identifier: {0:?}")]
    InvalidIdentifier(String),
    /// Identifier is a reserved SQL word or a protected system column.
    #[error("reserved name: {0:?}")]
    ReservedName(String),
    /// Field type is outside the supported column vocabulary.
    #[error("unsupported field type for a physical column: {0:?}")]
    UnknownType(String),
    /// Underlying database error.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// System columns present on every generated table. Never user-addressable —
/// `add_column`/`drop_column`/`rename_column` refuse them.
pub const SYSTEM_COLUMNS: &[&str] = &["id", "company_id", "active", "created_at", "updated_at"];

/// Namespace prefix for every generated table and thus every Blueprint's
/// technical model name. Reserves the blueprint namespace away from compiled
/// (`derive(Model)`) tables so the two can never collide.
pub const TABLE_PREFIX: &str = "x_";

/// A blocklist of SQL keywords refused as identifiers even though they match
/// the character pattern. Not exhaustive — this is defense in depth on top of
/// the strict pattern, the `x_` prefix, and the fixed type vocabulary; those
/// are the primary guarantees.
const RESERVED_WORDS: &[&str] = &[
    "select", "insert", "update", "delete", "drop", "alter", "create", "table",
    "from", "where", "join", "union", "and", "or", "not", "null", "true", "false",
    "user", "order", "group", "by", "into", "values", "set", "index", "constraint",
    "primary", "foreign", "references", "default", "grant", "revoke", "public",
    "with", "as", "on", "using", "distinct", "having", "limit", "offset",
];

/// Strict identifier check for anything interpolated into DDL: 1–48 chars,
/// lowercase ASCII, must start with a letter, `[a-z][a-z0-9_]*`, and not a
/// reserved word. This is the canonical validator for the blueprint path; the
/// host binary has an older private copy that should later delegate here.
pub fn validate_identifier(name: &str) -> Result<(), BlueprintError> {
    let len = name.len();
    if len == 0 || len > 48 {
        return Err(BlueprintError::InvalidIdentifier(name.to_string()));
    }
    let mut chars = name.chars();
    // Unwrap is safe: len > 0 checked above.
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(BlueprintError::InvalidIdentifier(name.to_string()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(BlueprintError::InvalidIdentifier(name.to_string()));
    }
    if RESERVED_WORDS.contains(&name) {
        return Err(BlueprintError::ReservedName(name.to_string()));
    }
    Ok(())
}

/// Validate a generated **table** name: a valid identifier that also carries the
/// [`TABLE_PREFIX`], so the mechanics can never create a table outside the
/// blueprint namespace even if a caller is buggy.
fn validate_table(table: &str) -> Result<(), BlueprintError> {
    validate_identifier(table)?;
    if !table.starts_with(TABLE_PREFIX) {
        return Err(BlueprintError::InvalidIdentifier(table.to_string()));
    }
    Ok(())
}

/// Validate a user column name: a valid identifier that isn't a protected
/// system column.
fn validate_column(column: &str) -> Result<(), BlueprintError> {
    validate_identifier(column)?;
    if SYSTEM_COLUMNS.contains(&column) {
        return Err(BlueprintError::ReservedName(column.to_string()));
    }
    Ok(())
}

/// Map an `ir_model_field.field_type` to a Postgres column type. Only scalar
/// and `many2one` (a UUID) types map to a physical column; relational
/// (`one2many`/`many2many`) types are not columns and are rejected here — they
/// are handled by the service layer in a later phase.
pub fn column_type(field_type: &str) -> Result<&'static str, BlueprintError> {
    Ok(match field_type {
        "string" | "char" => "VARCHAR(255)",
        "selection" => "VARCHAR(64)",
        "text" => "TEXT",
        "boolean" => "BOOLEAN",
        "integer" => "INTEGER",
        "float" | "number" => "DOUBLE PRECISION",
        "decimal" | "monetary" => "NUMERIC(16,2)",
        "date" => "DATE",
        "datetime" => "TIMESTAMPTZ",
        "uuid" | "many2one" => "UUID",
        "json" => "JSONB",
        other => return Err(BlueprintError::UnknownType(other.to_string())),
    })
}

/// Append an executed statement to the per-tenant DDL ledger, in the same
/// transaction as the DDL itself. `statement` is a bound parameter, not
/// interpolated.
async fn log_ddl(
    tx: &mut Transaction<'_, Postgres>,
    blueprint_id: Uuid,
    statement: &str,
) -> Result<(), BlueprintError> {
    sqlx::query("INSERT INTO blueprint_ddl_log (blueprint_id, statement) VALUES ($1, $2)")
        .bind(blueprint_id)
        .bind(statement)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Create the generated record table for a Blueprint, with the standard system
/// columns. `table` must be `x_`-prefixed and pass identifier validation.
pub async fn create_model_table(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    blueprint_id: Uuid,
) -> Result<(), BlueprintError> {
    validate_table(table)?;
    let stmt = format!(
        "CREATE TABLE {table} (\
         id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), \
         company_id UUID REFERENCES companies(id), \
         active BOOLEAN NOT NULL DEFAULT TRUE, \
         created_at TIMESTAMPTZ NOT NULL DEFAULT now(), \
         updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"
    );
    sqlx::query(&stmt).execute(&mut **tx).await?;
    log_ddl(tx, blueprint_id, &stmt).await?;
    Ok(())
}

/// Add a scalar (or `many2one` UUID) column to a Blueprint's table.
pub async fn add_column(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    column: &str,
    field_type: &str,
    blueprint_id: Uuid,
) -> Result<(), BlueprintError> {
    validate_table(table)?;
    validate_column(column)?;
    let col_type = column_type(field_type)?;
    let stmt = format!("ALTER TABLE {table} ADD COLUMN {column} {col_type}");
    sqlx::query(&stmt).execute(&mut **tx).await?;
    log_ddl(tx, blueprint_id, &stmt).await?;
    Ok(())
}

/// Drop a user column from a Blueprint's table. System columns are refused.
pub async fn drop_column(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    column: &str,
    blueprint_id: Uuid,
) -> Result<(), BlueprintError> {
    validate_table(table)?;
    validate_column(column)?;
    let stmt = format!("ALTER TABLE {table} DROP COLUMN {column}");
    sqlx::query(&stmt).execute(&mut **tx).await?;
    log_ddl(tx, blueprint_id, &stmt).await?;
    Ok(())
}

/// Rename a user column on a Blueprint's table. Both names must be valid,
/// non-system identifiers.
pub async fn rename_column(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    from: &str,
    to: &str,
    blueprint_id: Uuid,
) -> Result<(), BlueprintError> {
    validate_table(table)?;
    validate_column(from)?;
    validate_column(to)?;
    let stmt = format!("ALTER TABLE {table} RENAME COLUMN {from} TO {to}");
    sqlx::query(&stmt).execute(&mut **tx).await?;
    log_ddl(tx, blueprint_id, &stmt).await?;
    Ok(())
}

/// Drop a Blueprint's generated table entirely (used by blueprint delete).
pub async fn drop_model_table(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    blueprint_id: Uuid,
) -> Result<(), BlueprintError> {
    validate_table(table)?;
    let stmt = format!("DROP TABLE {table}");
    sqlx::query(&stmt).execute(&mut **tx).await?;
    log_ddl(tx, blueprint_id, &stmt).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_identifiers_pass() {
        for ok in ["x_widget", "widget", "line_total", "field2", "x_a1_b2"] {
            assert!(validate_identifier(ok).is_ok(), "{ok:?} should be valid");
        }
    }

    #[test]
    fn invalid_identifiers_rejected() {
        // Empty, too long, leading digit/underscore, uppercase, punctuation,
        // whitespace, and an injection attempt.
        let long = "a".repeat(49);
        for bad in [
            "",
            long.as_str(),
            "1abc",
            "_abc",
            "Widget",
            "x-y",
            "x y",
            "x;drop table users",
            "x_widget;--",
        ] {
            assert!(
                matches!(validate_identifier(bad), Err(BlueprintError::InvalidIdentifier(_))),
                "{bad:?} should be InvalidIdentifier"
            );
        }
    }

    #[test]
    fn reserved_words_rejected() {
        for word in ["select", "drop", "table", "user", "where", "public"] {
            assert!(
                matches!(validate_identifier(word), Err(BlueprintError::ReservedName(_))),
                "{word:?} should be ReservedName"
            );
        }
    }

    #[test]
    fn tables_require_x_prefix() {
        assert!(validate_table("x_widget").is_ok());
        // A perfectly valid identifier that isn't namespaced is refused as a table.
        assert!(matches!(
            validate_table("widget"),
            Err(BlueprintError::InvalidIdentifier(_))
        ));
    }

    #[test]
    fn system_columns_are_protected() {
        for sys in SYSTEM_COLUMNS {
            assert!(
                matches!(validate_column(sys), Err(BlueprintError::ReservedName(_))),
                "{sys:?} should be protected"
            );
        }
        assert!(validate_column("customer_name").is_ok());
    }

    #[test]
    fn column_type_covers_the_vocabulary() {
        let cases = [
            ("string", "VARCHAR(255)"),
            ("char", "VARCHAR(255)"),
            ("selection", "VARCHAR(64)"),
            ("text", "TEXT"),
            ("boolean", "BOOLEAN"),
            ("integer", "INTEGER"),
            ("float", "DOUBLE PRECISION"),
            ("number", "DOUBLE PRECISION"),
            ("decimal", "NUMERIC(16,2)"),
            ("monetary", "NUMERIC(16,2)"),
            ("date", "DATE"),
            ("datetime", "TIMESTAMPTZ"),
            ("uuid", "UUID"),
            ("many2one", "UUID"),
            ("json", "JSONB"),
        ];
        for (ft, pg) in cases {
            assert_eq!(column_type(ft).unwrap(), pg, "type {ft}");
        }
    }

    #[test]
    fn relational_and_unknown_types_rejected() {
        for ft in ["one2many", "many2many", "wat", "binary"] {
            assert!(
                matches!(column_type(ft), Err(BlueprintError::UnknownType(_))),
                "{ft:?} should be UnknownType"
            );
        }
    }
}
