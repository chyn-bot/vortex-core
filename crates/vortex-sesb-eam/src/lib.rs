//! # SESB Enterprise Asset Management (vertical plugin)
//!
//! The electrical-utility EAM for Sabah Electricity, built to
//! `SESB_EAM_BUILD_SPECIFICATION`. A self-contained vertical that owns
//! the `eam_*` schema (field-level parity is a hard requirement) while
//! composing core primitives — contacts, sequences, audit, the inventory
//! stock ledger (spare-part consumption), scheduler, mail and reporting.
//!
//! ## Build phases
//!
//! 1. **Foundation** (this) — reference/master data and the location
//!    hierarchy Region → Zon → Kawasan → Site → Substation → Bay.
//! 2. Equipment + specializations, components, parts (MNEC asset-IDs).
//! 3. Transmission / distribution / UGC networks.
//! 4. Operations: work orders + checklists, defects, inspections,
//!    condition monitoring, patrols, outages, vegetation.
//! 5. Planning & governance: plans, verification, approvals, agents.
//! 6. Analytics, dashboards and IEEE-1366 reliability reports.
//! 7. REST API, technician portal, Cerdik AI, jobs, maps & diagrams.

pub mod handlers;
pub mod plugin;
pub mod workflow;

pub use plugin::SesbEamPlugin;
