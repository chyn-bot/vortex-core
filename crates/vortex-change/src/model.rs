//! Change Request domain model — the row shape of `change_requests`.
//!
//! A [`ChangeRequest`] is the business-facing half of a CR. Its
//! lifecycle is driven by the generic [`vortex_workflow::WorkflowEngine`]
//! via the [`crate::cr_state_machine`] registered at plugin startup, so
//! this struct does not own its own state machine — it just stores the
//! workflow instance id that the engine walks.
//!
//! Fields that live here:
//! - the CR's stable technical data (number, title, description,
//!   category, criticality, rollback plan, requester);
//! - the planned execution window, which compliance cares about
//!   because changes outside their approved window are flagged;
//! - the FK to the `workflow_instances` row that tracks state.
//!
//! Fields that do **not** live here:
//! - `current_state` — lives on `workflow_instances.current_state`
//!   and is the single source of truth for the CR's state. Rendering
//!   code resolves it via the engine.
//! - approvals/transition history — live in `workflow_transitions`,
//!   chained to the WORM audit ledger by `audit_entry_id`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Category tags describe *what kind of change* is being requested.
/// These drive Cedar policies ("emergency changes may skip the queue
/// and go directly under_review", etc.) and reporting buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrCategory {
    /// Low-risk pre-approved changes that follow a documented
    /// runbook. Example: rotating an SSH key on a non-critical host.
    Routine,
    /// Changes following the standard review path — the default.
    Standard,
    /// CIP-010 "change requires approved CR" bucket — scheduled
    /// maintenance on a baselined asset. Usually needs both
    /// `change_approver` and an eSig on high-criticality assets.
    Maintenance,
    /// Out-of-band changes responding to an incident. Cedar can
    /// permit an expedited approval path for this category.
    Emergency,
}

impl CrCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            CrCategory::Routine => "routine",
            CrCategory::Standard => "standard",
            CrCategory::Maintenance => "maintenance",
            CrCategory::Emergency => "emergency",
        }
    }

    pub fn all() -> &'static [CrCategory] {
        &[
            CrCategory::Routine,
            CrCategory::Standard,
            CrCategory::Maintenance,
            CrCategory::Emergency,
        ]
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "routine" => Some(CrCategory::Routine),
            "standard" => Some(CrCategory::Standard),
            "maintenance" => Some(CrCategory::Maintenance),
            "emergency" => Some(CrCategory::Emergency),
            _ => None,
        }
    }
}

/// Criticality is the Low / Medium / High axis the rest of the core
/// uses (see CLAUDE.md — the asset graph already carries this
/// concept). On a CR it drives eSig requirements: per CIP-010,
/// `High` changes must be dual-signed before the `approve`
/// transition is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrCriticality {
    Low,
    Medium,
    High,
}

impl CrCriticality {
    pub fn as_str(&self) -> &'static str {
        match self {
            CrCriticality::Low => "low",
            CrCriticality::Medium => "medium",
            CrCriticality::High => "high",
        }
    }

    pub fn all() -> &'static [CrCriticality] {
        &[CrCriticality::Low, CrCriticality::Medium, CrCriticality::High]
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "low" => Some(CrCriticality::Low),
            "medium" => Some(CrCriticality::Medium),
            "high" => Some(CrCriticality::High),
            _ => None,
        }
    }
}

/// Mirror of the workflow state machine's state names. This is a
/// convenience for strongly-typed rendering code; the authoritative
/// value is the `current_state` string on the `workflow_instances`
/// row. Keep [`CrState::parse`] in lock-step with
/// [`crate::cr_state_machine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrState {
    Draft,
    Submitted,
    UnderReview,
    Approved,
    Rejected,
    Withdrawn,
    Closed,
}

impl CrState {
    pub fn as_str(&self) -> &'static str {
        match self {
            CrState::Draft => "draft",
            CrState::Submitted => "submitted",
            CrState::UnderReview => "under_review",
            CrState::Approved => "approved",
            CrState::Rejected => "rejected",
            CrState::Withdrawn => "withdrawn",
            CrState::Closed => "closed",
        }
    }

    /// Human-readable label for badge rendering. Kept separate from
    /// [`Self::as_str`] which must stay stable for DB round-tripping.
    pub fn label(&self) -> &'static str {
        match self {
            CrState::Draft => "Draft",
            CrState::Submitted => "Submitted",
            CrState::UnderReview => "Under Review",
            CrState::Approved => "Approved",
            CrState::Rejected => "Rejected",
            CrState::Withdrawn => "Withdrawn",
            CrState::Closed => "Closed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(CrState::Draft),
            "submitted" => Some(CrState::Submitted),
            "under_review" => Some(CrState::UnderReview),
            "approved" => Some(CrState::Approved),
            "rejected" => Some(CrState::Rejected),
            "withdrawn" => Some(CrState::Withdrawn),
            "closed" => Some(CrState::Closed),
            _ => None,
        }
    }

    /// True when no further transitions are possible on this CR.
    /// Mirrors the terminal set declared in [`crate::cr_state_machine`].
    pub fn is_terminal(&self) -> bool {
        matches!(self, CrState::Rejected | CrState::Withdrawn | CrState::Closed)
    }
}

/// A change request row. Matches the `change_requests` table created
/// by the plugin-owned migration `001_change_requests` (embedded in
/// this crate via [`crate::ChangeRequestPlugin::migrations`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRequest {
    pub id: Uuid,
    /// Human-facing number like `CR/2026/00042`. Stable for the life
    /// of the CR — used in audit entries and SIEM exports.
    pub number: String,
    pub title: String,
    pub description: String,
    pub category: CrCategory,
    pub criticality: CrCriticality,
    /// Optional rollback plan text — mandatory for `High` criticality
    /// in handler-level validation, but stored nullable so drafts can
    /// be saved incrementally without the plan filled in.
    pub rollback_plan: Option<String>,
    /// Planned execution window start (nullable — may not be known
    /// at draft time).
    pub planned_start: Option<DateTime<Utc>>,
    /// Planned execution window end.
    pub planned_end: Option<DateTime<Utc>>,
    pub requested_by: Uuid,
    /// FK into `workflow_instances` — this is where `current_state`
    /// actually lives. Every CR has exactly one workflow instance,
    /// created during the same transaction as the CR row.
    pub workflow_instance_id: Uuid,
    pub company_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_roundtrip() {
        for cat in CrCategory::all() {
            assert_eq!(CrCategory::parse(cat.as_str()), Some(*cat));
        }
        assert_eq!(CrCategory::parse("nonsense"), None);
    }

    #[test]
    fn criticality_roundtrip() {
        for c in CrCriticality::all() {
            assert_eq!(CrCriticality::parse(c.as_str()), Some(*c));
        }
    }

    #[test]
    fn state_roundtrip() {
        let all = [
            CrState::Draft,
            CrState::Submitted,
            CrState::UnderReview,
            CrState::Approved,
            CrState::Rejected,
            CrState::Withdrawn,
            CrState::Closed,
        ];
        for s in all {
            assert_eq!(CrState::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn terminal_states_match_state_machine() {
        // Keep in lock-step with state_machine.rs's `.terminal(...)` calls.
        assert!(CrState::Rejected.is_terminal());
        assert!(CrState::Withdrawn.is_terminal());
        assert!(CrState::Closed.is_terminal());
        assert!(!CrState::Draft.is_terminal());
        assert!(!CrState::Approved.is_terminal());
    }
}
