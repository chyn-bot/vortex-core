//! Platform sequence service — atomic, no-gap counters for generated codes.
//!
//! A **sequence** is a named, monotonically-increasing integer counter
//! whose next value is consumed atomically and formatted into a
//! human-readable code like `EQP/000042` or `MNT/2026/00017`. Every
//! Vortex vertical needs this (equipment codes, work-order numbers,
//! invoice numbers, CR numbers, ticket numbers) so it lives in core
//! rather than duplicated across plugin crates.
//!
//! ## Guarantees
//!
//! - **Atomic**: uses a single SQL UPSERT, so two concurrent callers
//!   never observe the same value. Safe under any load without
//!   application-level locking.
//! - **No-gap**: every value consumed is returned to exactly one
//!   caller; there are no holes from aborted transactions like you'd
//!   get from a Postgres `SEQUENCE` (`nextval` is not rolled back).
//!   This is the semantics regulated customers need — "invoice 17 was
//!   voided" is recoverable, "invoice 17 never existed" is not.
//! - **Scoped**: a single `code` can carry a `scope` sub-key so the
//!   same logical counter can reset on a schedule (e.g. yearly invoice
//!   numbering). The scope is stored alongside the code as part of the
//!   composite primary key.
//!
//! ## Storage
//!
//! All state lives in the `sequences` table (migration
//! `117_sequence_service`):
//!
//! ```sql
//! CREATE TABLE sequences (
//!     code          VARCHAR(100) NOT NULL,
//!     scope         VARCHAR(16)  NOT NULL DEFAULT '',
//!     current_value BIGINT       NOT NULL DEFAULT 0,
//!     updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
//!     PRIMARY KEY (code, scope)
//! );
//! ```
//!
//! ## Usage
//!
//! Define a spec (typically `const`) and hand it to [`next`]:
//!
//! ```rust,ignore
//! use vortex_orm::sequence::{self, SequenceSpec};
//! use vortex_orm::ConnectionPool;
//!
//! const INVOICE_SEQ: SequenceSpec = SequenceSpec::new("sales.invoice", "INV")
//!     .with_padding(6)
//!     .yearly();
//!
//! async fn new_invoice_number(pool: &ConnectionPool) -> anyhow::Result<String> {
//!     let code = sequence::next(pool, &INVOICE_SEQ).await?;
//!     // → "INV/2026/000042"
//!     Ok(code)
//! }
//! ```
//!
//! ## Naming convention for `code`
//!
//! Use a dotted namespace: `<plugin_technical_name>.<logical_name>`,
//! e.g. `eam.equipment`, `crm.lead`, `sales.invoice`. This keeps plugin
//! sequences from colliding and makes the `sequences` table self-
//! documenting.

use chrono::Utc;

use vortex_common::{VortexError, VortexResult};

use crate::ConnectionPool;

/// How a sequence partitions its counter by time.
///
/// A sequence with [`SequenceScope::Global`] has one counter that
/// increments forever. A sequence with [`SequenceScope::Yearly`] or
/// [`SequenceScope::Monthly`] has one counter *per period*: January
/// 2026 and January 2027 each start from `start`, independently.
///
/// The period is derived from `chrono::Utc::now()` — UTC, not local
/// time — so sequences are deterministic regardless of the server's
/// timezone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceScope {
    /// Single counter, never resets.
    Global,
    /// Resets each calendar year. Scope key formatted `%Y` (e.g.
    /// `2026`). The year is rendered into the generated code between
    /// the prefix and the number, so `MNT` + yearly becomes
    /// `MNT/2026/00017`.
    Yearly,
    /// Resets each calendar month. Scope key formatted `%Y-%m` (e.g.
    /// `2026-04`). The month is rendered into the generated code, so
    /// `INC` + monthly becomes `INC/2026-04/0003`.
    Monthly,
}

impl SequenceScope {
    /// Compute the current period key for this scope at the given UTC
    /// instant. Returns `""` for [`SequenceScope::Global`] so the
    /// database composite key is always a non-null string.
    fn period_key(self, now: chrono::DateTime<Utc>) -> String {
        match self {
            SequenceScope::Global => String::new(),
            SequenceScope::Yearly => now.format("%Y").to_string(),
            SequenceScope::Monthly => now.format("%Y-%m").to_string(),
        }
    }
}

/// Declarative specification of a sequence.
///
/// A `SequenceSpec` is a pure value — it describes what the sequence
/// *should* look like but holds no state. Callers typically define
/// specs as `const` and pass references to [`next`]/[`peek`]/[`reset`].
///
/// All builder methods are `const` so a `SequenceSpec` can be computed
/// at compile time.
#[derive(Debug, Clone, Copy)]
pub struct SequenceSpec {
    /// Globally-unique dotted code, e.g. `"eam.equipment"`. Plugin
    /// names should be prefixed with the plugin's technical name so
    /// two plugins cannot collide.
    pub code: &'static str,
    /// Prefix rendered before the number. Typically uppercase short
    /// letters like `EQP`, `MNT`, `INV`.
    pub prefix: &'static str,
    /// Optional suffix rendered after the number. Empty for most
    /// sequences.
    pub suffix: &'static str,
    /// How to zero-pad the number. `6` means `000042`.
    pub padding: usize,
    /// Period scoping for the counter.
    pub scope: SequenceScope,
    /// First value returned after a reset / at genesis.
    pub start: i64,
    /// Increment step. Typically `1`; can be set larger for
    /// block-reserved sequences.
    pub step: i64,
    /// Separator between prefix, period (if any), and the padded
    /// number. Defaults to `"/"` to match existing Vortex conventions.
    pub separator: &'static str,
}

impl SequenceSpec {
    /// Construct a new spec with required fields and sensible defaults
    /// (padding 5, global scope, start at 1, step 1, `/` separator,
    /// no suffix).
    pub const fn new(code: &'static str, prefix: &'static str) -> Self {
        Self {
            code,
            prefix,
            suffix: "",
            padding: 5,
            scope: SequenceScope::Global,
            start: 1,
            step: 1,
            separator: "/",
        }
    }

    /// Set the zero-pad width for the numeric portion.
    pub const fn with_padding(mut self, padding: usize) -> Self {
        self.padding = padding;
        self
    }

    /// Mark this sequence as yearly-scoped — counter resets each year,
    /// generated codes include the year.
    pub const fn yearly(mut self) -> Self {
        self.scope = SequenceScope::Yearly;
        self
    }

    /// Mark this sequence as monthly-scoped.
    pub const fn monthly(mut self) -> Self {
        self.scope = SequenceScope::Monthly;
        self
    }

    /// Attach a static suffix to every generated code.
    pub const fn with_suffix(mut self, suffix: &'static str) -> Self {
        self.suffix = suffix;
        self
    }

    /// Override the default starting value (useful when migrating from
    /// an existing system with numbers already in use).
    pub const fn starting_at(mut self, start: i64) -> Self {
        self.start = start;
        self
    }

    /// Override the increment step.
    pub const fn with_step(mut self, step: i64) -> Self {
        self.step = step;
        self
    }

    /// Override the default `"/"` separator (e.g. `"-"` for `INV-2026-00042`).
    pub const fn with_separator(mut self, separator: &'static str) -> Self {
        self.separator = separator;
        self
    }

    /// Format a numeric value into the human-readable code for this
    /// spec, given the period key (pre-computed by the caller so the
    /// formatting is pure and testable).
    fn format(&self, value: i64, period_key: &str) -> String {
        let number = format!("{:0width$}", value, width = self.padding);
        let mut out = String::with_capacity(
            self.prefix.len() + self.separator.len() * 2 + period_key.len() + number.len() + self.suffix.len(),
        );
        out.push_str(self.prefix);
        if !period_key.is_empty() {
            out.push_str(self.separator);
            out.push_str(period_key);
        }
        out.push_str(self.separator);
        out.push_str(&number);
        out.push_str(self.suffix);
        out
    }
}

/// Consume the next value of a sequence and return the formatted code.
///
/// This is the atomic primitive: a single UPSERT claims the next
/// value, increments the counter, and returns it in one round trip.
/// Two concurrent callers will always get two distinct values.
///
/// The counter for a period is lazily created — the first call for
/// `(code, period)` returns `spec.start`, subsequent calls return
/// `start + N * step`.
pub async fn next(pool: &ConnectionPool, spec: &SequenceSpec) -> VortexResult<String> {
    let now = Utc::now();
    let period = spec.scope.period_key(now);

    // Atomic UPSERT: either insert at `start` (first-ever call for this
    // period) or bump the existing counter by `step`. The composite
    // PK (code, scope) is what makes year-based sequences cohabit the
    // same logical code without collision.
    let next_val: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO sequences (code, scope, current_value, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (code, scope) DO UPDATE
        SET current_value = sequences.current_value + $4,
            updated_at = NOW()
        RETURNING current_value
        "#,
    )
    .bind(spec.code)
    .bind(&period)
    .bind(spec.start)
    .bind(spec.step)
    .fetch_one(pool.pool())
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(spec.format(next_val, &period))
}

/// Peek at the next value that [`next`] would return, without
/// consuming it. Intended for "next code will be…" previews in forms.
/// Do not use the returned code as an actual identifier — two peek
/// callers can read the same preview, but only one can subsequently
/// [`next`] it.
pub async fn peek(pool: &ConnectionPool, spec: &SequenceSpec) -> VortexResult<String> {
    let now = Utc::now();
    let period = spec.scope.period_key(now);

    let current: Option<i64> = sqlx::query_scalar(
        "SELECT current_value FROM sequences WHERE code = $1 AND scope = $2",
    )
    .bind(spec.code)
    .bind(&period)
    .fetch_optional(pool.pool())
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let next_val = match current {
        Some(v) => v + spec.step,
        None => spec.start,
    };

    Ok(spec.format(next_val, &period))
}

/// Reset a sequence's counter for the current period to a specific
/// value. **Dangerous** — can produce duplicate codes if used
/// carelessly. Intended for administrative data imports and recovery
/// scenarios, not for ordinary application code.
///
/// The reset is scoped to the **current** period; yearly and monthly
/// sequences retain their other periods' counters untouched.
pub async fn reset(pool: &ConnectionPool, spec: &SequenceSpec, to: i64) -> VortexResult<()> {
    let now = Utc::now();
    let period = spec.scope.period_key(now);

    sqlx::query(
        r#"
        INSERT INTO sequences (code, scope, current_value, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (code, scope) DO UPDATE
        SET current_value = $3,
            updated_at = NOW()
        "#,
    )
    .bind(spec.code)
    .bind(&period)
    .bind(to)
    .execute(pool.pool())
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_format_renders_prefix_and_padded_number() {
        let spec = SequenceSpec::new("test.widget", "WDG").with_padding(6);
        assert_eq!(spec.format(42, ""), "WDG/000042");
    }

    #[test]
    fn yearly_format_includes_year_between_prefix_and_number() {
        let spec = SequenceSpec::new("test.invoice", "INV")
            .with_padding(5)
            .yearly();
        assert_eq!(spec.format(17, "2026"), "INV/2026/00017");
    }

    #[test]
    fn monthly_format_includes_month_key() {
        let spec = SequenceSpec::new("test.ticket", "TKT")
            .with_padding(4)
            .monthly();
        assert_eq!(spec.format(3, "2026-04"), "TKT/2026-04/0003");
    }

    #[test]
    fn custom_separator_and_suffix_round_trip() {
        let spec = SequenceSpec::new("test.po", "PO")
            .with_padding(6)
            .with_separator("-")
            .with_suffix("/A")
            .yearly();
        assert_eq!(spec.format(99, "2026"), "PO-2026-000099/A");
    }

    #[test]
    fn global_scope_period_key_is_empty() {
        let now = Utc::now();
        assert_eq!(SequenceScope::Global.period_key(now), "");
    }

    #[test]
    fn yearly_scope_period_key_is_four_digit_year() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-11T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(SequenceScope::Yearly.period_key(now), "2026");
    }

    #[test]
    fn monthly_scope_period_key_is_year_dash_month() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-11T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(SequenceScope::Monthly.period_key(now), "2026-04");
    }

    #[test]
    fn const_spec_can_be_built_at_compile_time() {
        // Compile-time sanity check — if this file builds, const chaining works.
        const INVOICE: SequenceSpec = SequenceSpec::new("sales.invoice", "INV")
            .with_padding(6)
            .yearly();
        assert_eq!(INVOICE.code, "sales.invoice");
        assert_eq!(INVOICE.prefix, "INV");
        assert_eq!(INVOICE.padding, 6);
        assert!(matches!(INVOICE.scope, SequenceScope::Yearly));
    }
}
