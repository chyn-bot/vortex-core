//! Vortex Change Request — the first real plugin built on the
//! framework + workflow substrate.
//!
//! CLAUDE.md lists Change Management as a non-negotiable compliance
//! feature: "Change requires approved Change Request" under the
//! NERC CIP-010 Asset Baseline & Drift Detection requirement. This
//! plugin is what makes that real — every modification to a
//! baselined asset has to go through a reviewable, Cedar-gated,
//! WORM-audited change request before execution.
//!
//! # What this plugin is
//!
//! A small plugin crate (~1000 lines) that composes every core
//! primitive end-to-end:
//!
//! - **vortex-workflow**: the CR state machine (draft → submitted →
//!   under_review → approved/rejected → closed) is registered with
//!   the shared engine during plugin `state_machines()`. All state
//!   transitions run through `state.workflow.transition(...)` so
//!   they're audit-logged and Cedar-gated for free.
//! - **vortex-security**: every transition writes a
//!   `workflow_transition` entry to the WORM audit ledger. Auditors
//!   get a tamper-evident "who approved which CR when" trail.
//! - **vortex-policy**: transitions are gated by Cedar rules like
//!   "approver ≠ requester" (segregation of duties) and
//!   "high-criticality CRs require two distinct approvers".
//! - **vortex-framework**: routes + menu + plugin lifecycle plug
//!   in via the Plugin trait — no modification to `vortex-cli` is
//!   needed beyond a single registration line behind a feature flag.
//!
//! # What this plugin is NOT (yet)
//!
//! Scoped down to be the smallest-possible demonstrator. The Phase
//! 0.5 deliverable is the plugin skeleton + workflow integration +
//! happy-path handlers; a richer UI, attachment support, eSig on
//! high-criticality approvals, and scheduled auto-close of
//! stale CRs are deferred to later phases.

pub mod handlers;
pub mod model;
pub mod plugin;
pub mod state_machine;

pub use handlers::cr_routes;
pub use model::{ChangeRequest, CrCategory, CrCriticality, CrState};
pub use plugin::ChangeRequestPlugin;
pub use state_machine::cr_state_machine;
