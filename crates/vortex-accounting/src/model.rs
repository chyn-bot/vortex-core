//! Accounting models declared with `#[derive(Model)]`.
//!
//! Registry source of truth for the accounting tables: `Plugin::models()`
//! returns their `meta()`, projected into `ir_model` / `ir_model_field` after
//! migrations (see `vortex_orm::registry_sync`). Reproduces exactly the rows
//! migration `003_accounting_registry` used to hand-seed. These are registry
//! projections of the registered business fields only; `date` columns are
//! declared with `ui_type = "date"` (the ORM has no dedicated date storage
//! type yet, and the registry only needs the semantic type).

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_orm::prelude::Model;

/// Registry projection of `acc_move` (journal entries / invoices).
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "acc_move", module = "accounting", name = "acc_move", label = "Journal Entries")]
pub struct AccMove {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Number", ui_type = "string")]
    pub number: String,

    #[vortex(label = "Date", ui_type = "date")]
    pub move_date: String,

    #[vortex(label = "Type", selection = "entry,customer_invoice,customer_credit_note,vendor_bill,vendor_credit_note,payment")]
    pub move_type: String,

    #[vortex(label = "Partner", references = "contacts")]
    pub partner_id: Option<Uuid>,

    #[vortex(label = "Status", selection = "draft,posted,cancelled")]
    pub state: String,

    #[vortex(label = "Payment", selection = "not_paid,partial,paid,reversed")]
    pub payment_state: String,

    #[vortex(label = "Total", ui_type = "monetary")]
    pub total_amount: Option<f64>,

    #[vortex(label = "Open Amount", ui_type = "monetary")]
    pub amount_residual: Option<f64>,

    #[vortex(label = "Due Date", ui_type = "date")]
    pub due_date: String,

    // `ref` is a Rust keyword — modelled as a raw identifier; the macro strips
    // `r#` so it registers and maps to the column `ref`.
    #[vortex(label = "Reference", ui_type = "string")]
    pub r#ref: String,

    #[vortex(label = "Origin", ui_type = "string")]
    pub origin_ref: String,
}

/// Registry projection of `acc_account` (chart of accounts).
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "acc_account", module = "accounting", name = "acc_account", label = "Chart of Accounts")]
pub struct AccAccount {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Code", ui_type = "string")]
    pub code: String,

    #[vortex(label = "Account", ui_type = "string")]
    pub name: String,

    #[vortex(label = "Type", selection = "asset_cash,asset_bank,asset_receivable,asset_current,asset_fixed,asset_non_current,liability_payable,liability_current,liability_non_current,equity,income,income_other,expense,expense_depreciation,expense_direct_cost")]
    pub account_type: String,

    #[vortex(label = "Reconcilable")]
    pub reconcile: bool,

    #[vortex(label = "Active")]
    pub active: bool,
}
