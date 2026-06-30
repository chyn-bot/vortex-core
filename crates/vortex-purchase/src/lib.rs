//! # Vortex Purchase Plugin
//!
//! Procurement on top of the platform's primitives. A purchase order
//! moves through `draft → confirmed → received`, and receiving it posts
//! validated stock moves into inventory — the first module that
//! *composes* a primitive rather than defining one.
//!
//! | Concern        | Reused primitive                                  |
//! |----------------|---------------------------------------------------|
//! | Vendor         | core `contacts` (contact_type supplier/both)      |
//! | Product        | `vortex-inventory` `stock_product`                |
//! | Receiving bin  | `vortex-inventory` `stock_location` (internal)    |
//! | Goods receipt  | `vortex_inventory::post_move` (validated move)    |
//! | Currency       | commerce `currencies`                             |
//! | Numbering      | sequence `PO/000001`                              |
//! | Audit          | WORM ledger on create/confirm/receive/cancel      |
//!
//! Tables (`purchase_order`, `purchase_order_line`) are plugin-owned;
//! everything else is borrowed from core and the inventory primitive.

pub mod handlers;
pub mod plugin;

pub use plugin::PurchasePlugin;
