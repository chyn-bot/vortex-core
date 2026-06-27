//! Reusable list view — search, filter, sort, group, paginate.
//!
//! Every ERP model needs the same list pattern. This module provides
//! it as a declarative, zero-custom-HTML API:
//!
//! ```rust,ignore
//! let config = ListConfig::new("Contacts", "contacts")
//!     .column(ListColumn::new("code", "Code").sortable().code())
//!     .column(ListColumn::new("name", "Name").sortable().searchable())
//!     .column(ListColumn::new("email", "Email").searchable())
//!     .column(ListColumn::new("contact_type", "Type")
//!         .filterable(&[("customer", "Customer"), ("supplier", "Supplier")])
//!         .badge(&[("customer", "Customer", "badge-info"),
//!                   ("supplier", "Supplier", "badge-secondary")]))
//!     .column(ListColumn::new("active", "Status")
//!         .bool_badge("Active", "badge-success", "Archived", "badge-warning"))
//!     .detail_url("/contacts/{id}")
//!     .create("New Contact", "#create-modal")
//!     .default_sort("name");
//!
//! let params = ListParams::from_query(&query);
//! let result = execute_list(&db, &config, &params).await?;
//! let html = render_list(&config, &result, &params, "/contacts");
//! ```

pub mod config;
pub mod params;
pub mod query;
pub mod render;

pub use config::{CellRenderer, ListColumn, ListConfig};
pub use params::{ListParams, SortDir};
pub use query::{execute_list, ListResult};
pub use render::render_list;
