//! Vortex Chatter System
//!
//! Provides Odoo-like messaging, activities, and notifications on any record.
//!
//! # Features
//!
//! - **Messages**: Post comments and internal notes on any record
//! - **Activities**: Schedule tasks and reminders with due dates
//! - **Followers**: Subscribe users to record updates
//! - **Attachments**: Attach files to messages or records
//! - **Mentions**: @mention users in messages
//! - **Notifications**: In-app notification system

pub mod models;
pub mod service;
pub mod audit_bridge;
pub mod mention_parser;
pub mod traits;

// Re-exports for convenience
pub use models::*;
pub use service::{ChatterService, ChatterTimelineItem, FieldChange, MessageType, NotificationType};
pub use audit_bridge::{ChatterAuditEntry, FieldChangeDisplay};
pub use traits::Chattable;
