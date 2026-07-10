//! # Vortex Inventory Plugin
//!
//! A **generic, reusable stock primitive** — deliberately *not* tied to
//! any vertical. It gives the platform the four classic building blocks
//! of inventory management, modelled on a double-entry stock ledger:
//!
//! | Entity                   | Table                     | Role                              |
//! |--------------------------|---------------------------|-----------------------------------|
//! | Product / Part           | `stock_product`           | Catalogue of stockable items      |
//! | Product Category         | `stock_product_category`  | Hierarchical grouping             |
//! | Location                 | `stock_location`          | Real + virtual stock locations    |
//! | Stock Move               | `stock_move`              | Movement ledger (draft → done)    |
//! | Quant (on-hand)          | `stock_quant`             | Running balance per location      |
//!
//! ## Why this is core infrastructure, not a vertical
//!
//! The SESB EAM (and any future vertical) needs spare-part consumption,
//! goods receipts, and on-hand visibility. Rather than baking that into
//! the utility plugin, it lives here as a primitive the maintenance and
//! procurement modules build on — the same way `commerce` (currency /
//! UoM / tax) is shared. Units of measure are reused directly from the
//! commerce primitives (`uoms`).
//!
//! ## Primitives exercised
//!
//! - **Sequences** — `PRD/000001` products, `MOV/000001` moves
//! - **Audit ledger** — create/update/delete + field-level `Tracker`
//! - **Model registry** — products/locations/moves registered for the
//!   generic list/pivot/API layer
//! - **List framework** — searchable/filterable/groupable list views
//! - **Scheduler** — daily reorder-point alert
//! - **Reports** — On-Hand Valuation in HTML / CSV / JSON
//! - **i18n** — menu + field labels in English + Malay

pub mod handlers;
pub mod model;
pub mod plugin;
pub mod service;

pub use model::{StockLocation, StockLot, StockMove, StockProduct};
pub use plugin::InventoryPlugin;
pub use service::{move_sequence, post_move};
