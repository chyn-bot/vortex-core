//! Vortex Workflow — generic state machine engine.
//!
//! This crate is the reusable workflow primitive every approval-
//! or lifecycle-driven module (Change Request, Purchase Order,
//! Incident Management, Access Request, etc.) builds on top of.
//! CLAUDE.md lists "Multi-Level Approval Workflows" as a
//! non-negotiable compliance feature; this crate is the shared
//! machinery so each module doesn't re-invent it badly.
//!
//! # Architecture
//!
//! - [`machine`] — compile-time [`StateMachine`] definitions. A
//!   plugin declares its states + transitions as Rust constants;
//!   the engine validates transitions against that definition at
//!   runtime.
//! - [`instance`] — runtime [`WorkflowInstance`] data: a row in
//!   `workflow_instances` holding current state, state data, tenant
//!   scope, and timestamps. Every modified-at-runtime piece lives
//!   here, not in the static state machine.
//! - [`engine`] — [`WorkflowEngine`] service. Its one real method,
//!   `transition`, does the full cycle in a single transaction:
//!   load-for-update, validate transition, Cedar policy check,
//!   pre-hooks, write history row + audit ledger entry, update
//!   instance state, post-hooks, commit.
//! - [`store`] — Postgres persistence backend. Unit tests use
//!   an in-memory implementation; integration tests hit real DB.
//!
//! # Layering with audit and policy
//!
//! Every transition is both **audited** (written to the WORM audit
//! ledger so the sequence is tamper-evident) and **policy-checked**
//! (Cedar evaluates whether the actor is allowed to perform that
//! transition on that instance under current context). These two
//! guarantees are why the workflow engine lives in core rather
//! than being re-implemented per plugin — the audit and policy
//! ties are tricky to get right once, let alone N times.

pub mod engine;
pub mod error;
pub mod instance;
pub mod machine;
pub mod store;

pub use engine::{TransitionContext, TransitionOutcome, WorkflowEngine};
pub use error::{WorkflowError, WorkflowResult};
pub use instance::{InstanceId, WorkflowInstance};
pub use machine::{State, StateMachine, Transition, WorkflowType};
pub use store::{InMemoryWorkflowStore, PgWorkflowStore, TransitionRecord, WorkflowStore};
