//! # Vortex Maintenance Plugin (CMMS)
//!
//! A **generic maintenance-management layer** — not a vertical. It gives
//! the platform the core CMMS building blocks that any asset-intensive
//! domain reuses:
//!
//! | Entity         | Table                     | Role                                |
//! |----------------|---------------------------|-------------------------------------|
//! | Asset          | `maint_asset`             | Generic asset register              |
//! | Asset Category | `maint_asset_category`    | Hierarchical grouping               |
//! | Work Order     | `maint_work_order`        | Corrective/preventive/inspection    |
//! | WO Part        | `maint_work_order_part`   | Spare parts consumed on a WO        |
//! | Plan           | `maint_plan`              | Preventive plan → generates WOs      |
//!
//! ## Composes primitives, doesn't reinvent them
//!
//! - **Inventory** — completing a work order consumes its parts as stock
//!   moves out of a location via `vortex_inventory::post_move`.
//! - **Scheduler** — a daily action turns due plans into draft work
//!   orders and advances each plan's next date.
//! - **Contacts** — asset vendor is a core contact.
//!
//! ## The specialization seam
//!
//! The SESB electrical EAM (and any other vertical) attaches its
//! equipment-type detail tables to `maint_asset.id` and layers its
//! reliability analytics on the work-order history — without forking
//! this base.

pub mod handlers;
pub mod plugin;

pub use plugin::MaintenancePlugin;
