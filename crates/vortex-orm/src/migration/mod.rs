//! Migration loading and management
//!
//! This module provides utilities for loading dialect-specific migrations
//! from a structured directory layout.

mod loader;

pub use loader::{MigrationLoader, MigrationEntry, MigrationMetadata};
