//! Vortex Policy Engine — ABAC over Cedar.
//!
//! This crate provides attribute-based access control that layers on top of
//! the coarse-grained RBAC in [`vortex-security`]. RBAC answers *"can this
//! role CRUD this table?"*, which is all you need for generic model access.
//! The policy engine answers *"can this specific user perform this specific
//! action on this specific resource under these specific conditions?"* —
//! the questions that ERP workflows actually ask:
//!
//! - *"Can Alice approve work order WO-2026-00123, given that she is the
//!   requester and the org requires segregation of duties?"*  → deny
//! - *"Can Bob (inspector) sign off equipment EQP-001234, given that its
//!   region is Sabah and Bob's assigned region is Sabah?"*  → permit
//! - *"Can Carol (cost-center manager) approve a PO for RM 85,000, given
//!   that her spending limit for CC-1001 is RM 100,000?"*  → permit
//!
//! None of these can be expressed as a SQL domain filter or a CRUD bit.
//!
//! # Architecture
//!
//! - [`PolicyService`] is the top-level service. Handlers call
//!   [`PolicyService::check`] with a principal, action, resource, and
//!   optional context. It returns a [`Decision`] which is either
//!   [`Decision::Allow`] or [`Decision::Deny`] with the determining
//!   policy ids.
//! - Policies are stored in the `policy_rules` table (migration 115) and
//!   loaded at startup. The service holds them behind an `RwLock` so a
//!   future admin endpoint can reload without a restart.
//! - The policy text uses the Cedar language as-is — no custom DSL. Cedar
//!   is an IETF-published ABAC language with a formal verifier, which is
//!   exactly what a compliance audit needs.
//!
//! # Relationship to the WORM audit ledger
//!
//! Every `Deny` decision produced by this service should be logged to
//! the [`vortex-security::AuditLog`] as an `AccessDenied` entry so the
//! WORM ledger has a record of access attempts. The service itself does
//! not hold a reference to the audit log — that's the caller's job, to
//! keep this crate from depending on vortex-security.

pub mod entities;
pub mod error;
pub mod service;
pub mod store;

pub use entities::{PolicyPrincipal, PolicyResource};
pub use error::{PolicyError, PolicyResult};
pub use service::{Decision, PolicyService};
pub use store::{PgPolicyStore, PolicyRecord, PolicyStore};
