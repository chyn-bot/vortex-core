//! Inventory models declared with `#[derive(Model)]`.
//!
//! These are the **registry source of truth** for the inventory tables:
//! `Plugin::models()` returns their `meta()`, and the host projects them into
//! `ir_model` / `ir_model_field` after migrations (see
//! `vortex_orm::registry_sync`). They reproduce exactly the rows that
//! migrations `002_inventory_registry` and `004_lot_registry` used to
//! hand-seed — same fields, types, labels, relations, selection options, and
//! ordering — so a database seeded either way is identical. Once the derive
//! path is verified at runtime, that hand-seed SQL becomes redundant.
//!
//! Each struct models only the **registered** business fields; the primary key
//! and system columns are excluded from the registry, matching the seeds.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_orm::prelude::Model;

/// Registry projection of `stock_product`.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "stock_product", module = "inventory", name = "stock_product", label = "Products")]
pub struct StockProduct {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Code", ui_type = "string")]
    pub code: String,

    #[vortex(label = "Name", ui_type = "string")]
    pub name: String,

    #[vortex(label = "Category", references = "stock_product_category")]
    pub category_id: Option<Uuid>,

    #[vortex(label = "Type", selection = "stockable,consumable,service")]
    pub product_type: String,

    #[vortex(label = "Tracking", selection = "none,lot,serial")]
    pub tracking: String,

    #[vortex(label = "Cost", ui_type = "monetary")]
    pub cost: Option<f64>,

    #[vortex(label = "Reorder Min", ui_type = "number")]
    pub reorder_min: Option<f64>,

    #[vortex(label = "Active")]
    pub active: bool,
}

/// Registry projection of `stock_location`.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "stock_location", module = "inventory", name = "stock_location", label = "Locations")]
pub struct StockLocation {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Code", ui_type = "string")]
    pub code: String,

    #[vortex(label = "Name", ui_type = "string")]
    pub name: String,

    #[vortex(label = "Type", selection = "internal,supplier,customer,inventory,transit")]
    pub location_type: String,

    #[vortex(label = "Parent", references = "stock_location")]
    pub parent_id: Option<Uuid>,

    #[vortex(label = "Active")]
    pub active: bool,
}

/// Registry projection of `stock_move`.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "stock_move", module = "inventory", name = "stock_move", label = "Stock Moves")]
pub struct StockMove {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Reference", ui_type = "string")]
    pub reference: String,

    #[vortex(label = "Product", references = "stock_product")]
    pub product_id: Option<Uuid>,

    #[vortex(label = "Quantity", ui_type = "number")]
    pub quantity: Option<f64>,

    #[vortex(label = "From", references = "stock_location")]
    pub source_location_id: Option<Uuid>,

    #[vortex(label = "To", references = "stock_location")]
    pub dest_location_id: Option<Uuid>,

    #[vortex(label = "Status", selection = "draft,done,cancelled")]
    pub state: String,
}

/// Registry projection of `stock_lot`.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "stock_lot", module = "inventory", name = "stock_lot", label = "Lots / Serials")]
pub struct StockLot {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Number", ui_type = "string")]
    pub name: String,

    #[vortex(label = "Product", references = "stock_product")]
    pub product_id: Option<Uuid>,

    #[vortex(label = "Type", selection = "lot,serial")]
    pub lot_type: String,

    #[vortex(label = "Active")]
    pub active: bool,
}
