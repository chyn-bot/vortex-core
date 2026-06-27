//! Platform commerce primitives — currencies, units of measure, taxes.
//!
//! Every commerce-adjacent vertical (Sales, Purchasing, Inventory,
//! Manufacturing, Finance, Services) needs the same three foundations:
//!
//! - **Currencies** — ISO 4217 codes, symbols, rounding rules, and a
//!   time-series of exchange rates so historical amounts convert
//!   deterministically.
//! - **Units of Measure** — a category-scoped conversion graph so
//!   "5 kg" can be compared to "5000 g" without the plugin author
//!   reinventing the factor table.
//! - **Taxes** — a minimal percent/fixed model with sale/purchase
//!   direction and inclusive/exclusive semantics, covering Malaysian
//!   SST, GST-style VATs, and per-line-item fees without reaching
//!   for Odoo's full `account.tax` machinery.
//!
//! Pure-function conversion and rounding logic is unit-tested here
//! (no DB required); DB-backed lookups ([`currency::get_rate`],
//! [`currency::convert_amount`]) hit the `currencies`, `currency_rates`,
//! `uoms`, `uom_categories`, and `taxes` tables from core migration
//! `119_commerce_primitives`.
//!
//! ## What this module deliberately does NOT provide
//!
//! - **Compound taxes** (tax on tax) and tax groups — these need a
//!   richer data model and the plugin that needs them will define it
//!   as an extension.
//! - **Historical rate fetching from a provider** — the scheduler
//!   primitive from Phase 0.7 makes this a one-file plugin; it does
//!   not belong in the core `commerce` module.
//! - **Chart of accounts, journal entries, ledger postings** — these
//!   are the job of a Finance plugin, not a platform primitive.
//! - **Per-company UoM overrides** — commerce uses the single
//!   platform-wide catalog; a vertical that needs per-tenant custom
//!   units can layer its own table on top.
//! - **Custom `Money` newtype** — amounts are stored as
//!   `(amount: Decimal, currency_id: Uuid)` pairs on domain tables;
//!   a typed wrapper that carries the currency through arithmetic
//!   is useful but can land later without affecting this module.
//!
//! These cuts keep the primitive set small enough to audit in one
//! sitting while still being *useful* to every vertical that ever
//! touches money or physical quantities.

pub mod currency;
pub mod tax;
pub mod uom;

pub use currency::{
    convert_amount, get_rate, round_to_currency, Currency, CurrencyRate,
};
pub use tax::{compute_tax_amount, Tax, TaxAmountType, TaxComputation, TaxTypeUse};
pub use uom::{convert_uom, Uom, UomCategory, UomType};
