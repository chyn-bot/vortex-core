//! High-throughput bulk insert via PostgreSQL `COPY ... FROM STDIN`.
//!
//! Row-by-row `INSERT` (even batched through an ORM) tops out well below what
//! a mass-write path needs: a billing run that finalises hundreds of thousands
//! of rows in a fixed window, a data import, a recompute job. `COPY` is the
//! Postgres-native bulk ingest path — one round trip streams the whole batch,
//! bypassing per-row statement planning and network chatter — and is typically
//! an order of magnitude faster than individual inserts.
//!
//! This is a **core** primitive, not a billing one: any vertical with a
//! mass-write step can reach for it. It deliberately stays close to the metal
//! — it does not go through the ORM's audit/computed-field machinery, because
//! its whole purpose is to skip per-row overhead. Callers that need an audit
//! trail for a bulk write should emit a single summary audit event for the
//! batch (see `AuditLog`), not one per row.
//!
//! # Format
//!
//! Values are sent in Postgres [text format]: tab-separated columns, one row
//! per line, `\N` for `NULL`, with the handful of special characters escaped.
//! Each value is the *textual* representation Postgres would parse for that
//! column type — `"42"`, `"12.50"`, `"t"`/`"f"` for bool, an ISO-8601 string
//! for a timestamp, a UUID string, a JSON string for `jsonb`. The caller owns
//! producing correct text for the target column; malformed text surfaces as a
//! `COPY` parse error from Postgres, not a silent corruption.
//!
//! Identifiers (table and columns) are validated and double-quoted, so a
//! caller-supplied name can never break out of the statement.
//!
//! [text format]: https://www.postgresql.org/docs/current/sql-copy.html
//!
//! # Example
//!
//! ```rust,ignore
//! use vortex_orm::bulk::BulkCopy;
//!
//! let mut copy = BulkCopy::new("bill", &["id", "account_id", "total_amount"])?;
//! for bill in &bills {
//!     copy.row(vec![
//!         Some(bill.id.to_string()),
//!         Some(bill.account_id.to_string()),
//!         Some(bill.total.to_string()),
//!     ]);
//! }
//! let written = copy.execute(pool).await?;
//! ```

use sqlx::postgres::{PgPool, PgPoolCopyExt};

/// Maximum identifier length we accept for a table or column name. Matches the
/// blueprint DDL validator so bulk targets and generated tables share limits.
const MAX_IDENT_LEN: usize = 48;

/// Validate a table or column identifier for interpolation into a `COPY`
/// statement: 1–[`MAX_IDENT_LEN`] chars, must start with a lowercase letter,
/// then `[a-z0-9_]`. We additionally double-quote every identifier in the
/// emitted SQL, so this is defence-in-depth, not the only guard. Reserved
/// words are *not* rejected (a legitimately-named `default`/`user` column is
/// fine once quoted) — the character whitelist alone prevents injection.
fn valid_ident(name: &str) -> Result<(), String> {
    let len = name.len();
    if len == 0 || len > MAX_IDENT_LEN {
        return Err(format!("invalid identifier length: {name:?}"));
    }
    let mut chars = name.chars();
    // Safe: len > 0 checked above.
    if !chars.next().unwrap().is_ascii_lowercase() {
        return Err(format!("identifier must start with a lowercase letter: {name:?}"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(format!("identifier has illegal characters: {name:?}"));
    }
    Ok(())
}

/// Escape one field into Postgres COPY text format. `None` becomes the null
/// marker `\N`; otherwise the four structural characters (backslash, tab,
/// newline, carriage return) are backslash-escaped so they cannot be read as
/// a column or row boundary.
fn escape_field(value: &Option<String>, out: &mut String) {
    match value {
        None => out.push_str("\\N"),
        Some(s) => {
            for ch in s.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '\t' => out.push_str("\\t"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    other => out.push(other),
                }
            }
        }
    }
}

/// A pending bulk `COPY` insert: a target table, a fixed column list, and the
/// rows accumulated so far. Build it, push rows, then [`BulkCopy::execute`].
pub struct BulkCopy {
    table: String,
    columns: Vec<String>,
    /// Serialized text-format body, appended to as rows are added, so we never
    /// hold a second copy of the data. One line per row, terminated by `\n`.
    body: String,
    rows: usize,
}

impl BulkCopy {
    /// Start a bulk insert into `table` over `columns`. Identifiers are
    /// validated up front so a bad name fails here, not mid-stream.
    pub fn new(table: &str, columns: &[&str]) -> Result<Self, String> {
        valid_ident(table)?;
        if columns.is_empty() {
            return Err("BulkCopy requires at least one column".to_string());
        }
        for c in columns {
            valid_ident(c)?;
        }
        Ok(Self {
            table: table.to_string(),
            columns: columns.iter().map(|c| c.to_string()).collect(),
            body: String::new(),
            rows: 0,
        })
    }

    /// Number of columns each row must supply.
    pub fn width(&self) -> usize {
        self.columns.len()
    }

    /// Rows staged so far.
    pub fn len(&self) -> usize {
        self.rows
    }

    pub fn is_empty(&self) -> bool {
        self.rows == 0
    }

    /// Append one row. `values` must have exactly [`BulkCopy::width`] elements,
    /// positionally matching the column list; `None` writes SQL `NULL`.
    ///
    /// Returns an error on arity mismatch rather than silently padding, so a
    /// column-count bug fails loudly at the call site.
    pub fn row(&mut self, values: Vec<Option<String>>) -> Result<&mut Self, String> {
        if values.len() != self.columns.len() {
            return Err(format!(
                "row has {} values but {} columns were declared",
                values.len(),
                self.columns.len()
            ));
        }
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                self.body.push('\t');
            }
            escape_field(v, &mut self.body);
        }
        self.body.push('\n');
        self.rows += 1;
        Ok(self)
    }

    /// The `COPY` statement this insert will run. Identifiers are double-quoted;
    /// `valid_ident` already guarantees they contain no quote character.
    fn copy_statement(&self) -> String {
        let cols = self
            .columns
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "COPY \"{}\" ({}) FROM STDIN WITH (FORMAT text)",
            self.table, cols
        )
    }

    /// Stream all staged rows to Postgres in a single `COPY`. Returns the
    /// number of rows written. A no-op (zero rows) returns `Ok(0)` without
    /// touching the connection.
    ///
    /// This is not itself transactional — wrap the call in a transaction if the
    /// batch must be all-or-nothing relative to other work. A `COPY` that fails
    /// mid-stream (e.g. a text value the target column rejects) aborts the whole
    /// copy: no partial rows land.
    pub async fn execute(&self, pool: &PgPool) -> Result<u64, String> {
        if self.rows == 0 {
            return Ok(0);
        }
        let mut copy = pool
            .copy_in_raw(&self.copy_statement())
            .await
            .map_err(|e| format!("COPY start failed: {e}"))?;
        copy.send(self.body.as_bytes())
            .await
            .map_err(|e| format!("COPY send failed: {e}"))?;
        let written = copy
            .finish()
            .await
            .map_err(|e| format!("COPY finish failed: {e}"))?;
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_identifiers() {
        assert!(BulkCopy::new("bill; drop table", &["id"]).is_err());
        assert!(BulkCopy::new("Bill", &["id"]).is_err()); // uppercase
        assert!(BulkCopy::new("bill", &["id\"; --"]).is_err());
        assert!(BulkCopy::new("bill", &[]).is_err()); // no columns
        assert!(BulkCopy::new("bill", &["id", "account_id"]).is_ok());
    }

    #[test]
    fn escapes_text_format_specials() {
        let mut out = String::new();
        escape_field(&Some("a\tb\nc\\d\re".to_string()), &mut out);
        assert_eq!(out, "a\\tb\\nc\\\\d\\re");

        out.clear();
        escape_field(&None, &mut out);
        assert_eq!(out, "\\N");

        out.clear();
        escape_field(&Some("plain".to_string()), &mut out);
        assert_eq!(out, "plain");
    }

    #[test]
    fn enforces_row_arity() {
        let mut c = BulkCopy::new("bill", &["id", "total"]).unwrap();
        assert!(c.row(vec![Some("1".into())]).is_err());
        assert!(c.row(vec![Some("1".into()), None]).is_ok());
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn builds_quoted_statement_and_body() {
        let mut c = BulkCopy::new("batch_run_item", &["run_id", "item_key"]).unwrap();
        c.row(vec![Some("r1".into()), Some("acct-1".into())]).unwrap();
        c.row(vec![Some("r1".into()), None]).unwrap();
        assert_eq!(
            c.copy_statement(),
            "COPY \"batch_run_item\" (\"run_id\", \"item_key\") FROM STDIN WITH (FORMAT text)"
        );
        assert_eq!(c.body, "r1\tacct-1\nr1\t\\N\n");
    }
}
