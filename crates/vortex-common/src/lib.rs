//! Vortex Common - Shared types, errors, and utilities
//!
//! This crate provides foundational types used across all Vortex components.

pub mod error;
pub mod types;
pub mod context;

pub use error::{VortexError, VortexResult};
pub use types::*;
pub use context::Context;
