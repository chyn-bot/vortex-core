//! The `IwkBill` model — registry projection of the `iwk_bill` table.
//!
//! `Plugin::models()` returns `IwkBill::meta()`, which the host syncs into
//! `ir_model` / `ir_model_field` after migrations — so the bill shows up in
//! the generic REST API and report builder. The list and the branded bill
//! page in `handlers.rs` are hand-built (not generated), because the bill has
//! a bespoke printed layout. Fields here are typed as display strings: this
//! struct is metadata only (never `query_as`'d), so it stays decoupled from
//! the table's precise SQL column types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_orm::prelude::Model;

/// Registry projection of the `iwk_bill` table (the sewerage services bill).
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "iwk_bill", module = "iwk", name = "iwk_bill", label = "IWK Bill")]
pub struct IwkBill {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Bill No", ui_type = "string")]
    pub bill_no: Option<String>,

    #[vortex(label = "Account No", ui_type = "string")]
    pub account_no: String,

    #[vortex(label = "Category", selection = "domestic,commercial")]
    pub category: String,

    #[vortex(label = "System Type", selection = "connected,individual")]
    pub system_type: String,

    #[vortex(label = "Bill Date", ui_type = "string")]
    pub bill_date: Option<String>,

    #[vortex(label = "Due Date", ui_type = "string")]
    pub due_date: Option<String>,

    #[vortex(label = "Total (RM)", ui_type = "string")]
    pub total: Option<String>,

    #[vortex(label = "State", selection = "issued,paid,cancelled")]
    pub record_state: String,
}
