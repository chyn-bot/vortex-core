//! Sales models declared with `#[derive(Model)]`.
//!
//! Registry source of truth for the sales tables; reproduces migration
//! `002_sales_registry`. See `vortex_orm::registry_sync`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_orm::prelude::Model;

/// Registry projection of `sales_order`.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "sales_order", module = "sales", name = "sales_order", label = "Sales Orders")]
pub struct SalesOrder {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Number", ui_type = "string")]
    pub number: String,

    #[vortex(label = "Customer", references = "contacts")]
    pub customer_id: Option<Uuid>,

    #[vortex(label = "Order Date", ui_type = "date")]
    pub order_date: String,

    #[vortex(label = "Status", selection = "draft,confirmed,delivered,cancelled")]
    pub state: String,

    #[vortex(label = "Total", ui_type = "monetary")]
    pub total_amount: Option<f64>,
}
