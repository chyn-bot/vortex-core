//! # Vortex Sales Plugin
//!
//! Order-to-cash on top of the platform's primitives. A sales order
//! moves through `draft → confirmed → delivered`, delivery posts
//! stock moves OUT of inventory, and one click bridges the order into
//! an accounting customer invoice carrying real taxes and LHDN
//! e-invoice classifications.
//!
//! | Concern         | Reused primitive                                   |
//! |-----------------|----------------------------------------------------|
//! | Customer        | core `contacts` (contact_type customer/both)       |
//! | Product         | `vortex-inventory` `stock_product` (+ sales defaults) |
//! | Ship-from bin   | `vortex-inventory` `stock_location` (internal)     |
//! | Goods delivery  | `vortex_inventory::post_move` (internal → customer)|
//! | Invoice         | `vortex_accounting::documents::create_invoice`     |
//! | Currency        | commerce `currencies`                              |
//! | Numbering       | sequence `SO/000001`                               |
//! | Audit           | WORM ledger on create/confirm/deliver/cancel       |
//!
//! Tables (`sales_order`, `sales_order_line`) are plugin-owned;
//! everything else is borrowed.

pub mod handlers;
pub mod model;
pub mod plugin;
pub mod richtext;

pub use plugin::SalesPlugin;
pub use model::SalesOrder;
