//! Purchase models declared with `#[derive(Model)]`.
//!
//! Registry source of truth for the purchase tables; reproduces migration
//! `002_purchase_registry`. See `vortex_orm::registry_sync`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_orm::prelude::Model;

/// Registry projection of `purchase_order`.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "purchase_order", module = "purchase", name = "purchase_order", label = "Purchase Orders")]
pub struct PurchaseOrder {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Number", ui_type = "string")]
    pub number: String,

    #[vortex(label = "Vendor", references = "contacts")]
    pub vendor_id: Option<Uuid>,

    #[vortex(label = "Order Date", ui_type = "date")]
    pub order_date: String,

    #[vortex(label = "Status", selection = "draft,confirmed,received,cancelled")]
    pub state: String,

    #[vortex(label = "Total", ui_type = "monetary")]
    pub total_amount: Option<f64>,
}
