//! # Vortex Accounting Plugin
//!
//! The platform's generic accounting base: chart of accounts, journals,
//! and double-entry journal entries, with a small service API that other
//! modules **adopt** instead of inventing their own charge/invoice tables.
//!
//! | Concern    | Reused primitive                                   |
//! |------------|----------------------------------------------------|
//! | Partner    | core `contacts` (customers / suppliers)            |
//! | Currency   | commerce `currencies`                              |
//! | Taxes      | commerce `taxes`                                   |
//! | Numbering  | sequence service (`SAL/2026/00042`, per journal)   |
//! | Audit      | WORM ledger on post / reverse                      |
//!
//! Design pillars (see `DESIGN.md`):
//! - **Unified move model** — an invoice/bill *is* an `acc_move` with a
//!   `move_type`; one posting engine, one immutability rule.
//! - **Posted = immutable** — enforced by DB triggers; corrections are
//!   reversal entries, never edits.
//! - **Balance enforced at posting** — Σdebit == Σcredit in one
//!   transaction, plus the company lock date.
//!
//! Adopting modules call [`service::create_and_post`] /
//! [`service::create_move`] / [`service::reverse_move`] — see the module
//! docs for an end-to-end example.

pub mod documents;
pub mod handlers;
pub mod handlers_documents;
pub mod handlers_tax;
pub mod plugin;
pub mod reports;
pub mod service;
pub mod tax;

pub use plugin::AccountingPlugin;
pub use documents::{
    create_invoice, post_invoice, refresh_document_totals, refresh_payment_state,
    register_payment, InvoiceLine, NewInvoice, NewPayment, PaymentDirection,
};
pub use service::{
    account_by_code, account_by_type, create_and_post, create_move, default_account,
    journal_by_code, move_sequence_for, post_move, reverse_move, MoveLine, NewMove,
};
