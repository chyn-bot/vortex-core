//! Maintenance Workflow Services
//!
//! Work Order state machine and transition logic per SESB spec

use chrono::Utc;
use uuid::Uuid;

use vortex_common::{VortexResult, VortexError};
use vortex_common::error::RecordId;
use vortex_orm::ConnectionPool;

/// Work Order States
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkOrderState {
    /// Initial state, WO being drafted
    Draft,
    /// WO scheduled for execution
    Scheduled,
    /// Work is in progress
    InProgress,
    /// Work temporarily on hold
    OnHold,
    /// Work completed
    Completed,
    /// WO cancelled
    Cancelled,
}

impl WorkOrderState {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkOrderState::Draft => "draft",
            WorkOrderState::Scheduled => "scheduled",
            WorkOrderState::InProgress => "in_progress",
            WorkOrderState::OnHold => "on_hold",
            WorkOrderState::Completed => "completed",
            WorkOrderState::Cancelled => "cancelled",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "draft" => Some(WorkOrderState::Draft),
            "scheduled" => Some(WorkOrderState::Scheduled),
            "in_progress" => Some(WorkOrderState::InProgress),
            "on_hold" => Some(WorkOrderState::OnHold),
            "completed" => Some(WorkOrderState::Completed),
            "cancelled" => Some(WorkOrderState::Cancelled),
            _ => None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, WorkOrderState::Completed | WorkOrderState::Cancelled)
    }
}

/// Work Order Actions that trigger state transitions
#[derive(Debug, Clone)]
pub enum WorkOrderAction {
    /// Schedule the work order for execution
    Schedule,
    /// Start work on the order
    Start,
    /// Put work on hold
    Hold { reason: String },
    /// Resume work from hold
    Resume,
    /// Complete the work order
    Complete,
    /// Cancel the work order
    Cancel { reason: String },
}

impl WorkOrderAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkOrderAction::Schedule => "schedule",
            WorkOrderAction::Start => "start",
            WorkOrderAction::Hold { .. } => "hold",
            WorkOrderAction::Resume => "resume",
            WorkOrderAction::Complete => "complete",
            WorkOrderAction::Cancel { .. } => "cancel",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            WorkOrderAction::Hold { reason } => Some(reason),
            WorkOrderAction::Cancel { reason } => Some(reason),
            _ => None,
        }
    }
}

/// Work Order State Machine
pub struct WorkOrderStateMachine;

impl WorkOrderStateMachine {
    /// Check if a transition is valid from current state with given action
    pub fn can_transition(current: &WorkOrderState, action: &WorkOrderAction) -> bool {
        Self::next_state(current, action).is_some()
    }

    /// Get the next state for a given current state and action
    ///
    /// State diagram:
    /// ```text
    /// draft → scheduled → in_progress ↔ on_hold → completed
    ///   ↓         ↓            ↓
    /// cancelled ←─────────────────
    /// ```
    pub fn next_state(current: &WorkOrderState, action: &WorkOrderAction) -> Option<WorkOrderState> {
        match (current, action) {
            // From Draft
            (WorkOrderState::Draft, WorkOrderAction::Schedule) => Some(WorkOrderState::Scheduled),
            (WorkOrderState::Draft, WorkOrderAction::Cancel { .. }) => Some(WorkOrderState::Cancelled),

            // From Scheduled
            (WorkOrderState::Scheduled, WorkOrderAction::Start) => Some(WorkOrderState::InProgress),
            (WorkOrderState::Scheduled, WorkOrderAction::Cancel { .. }) => Some(WorkOrderState::Cancelled),

            // From InProgress
            (WorkOrderState::InProgress, WorkOrderAction::Hold { .. }) => Some(WorkOrderState::OnHold),
            (WorkOrderState::InProgress, WorkOrderAction::Complete) => Some(WorkOrderState::Completed),
            (WorkOrderState::InProgress, WorkOrderAction::Cancel { .. }) => Some(WorkOrderState::Cancelled),

            // From OnHold
            (WorkOrderState::OnHold, WorkOrderAction::Resume) => Some(WorkOrderState::InProgress),
            (WorkOrderState::OnHold, WorkOrderAction::Cancel { .. }) => Some(WorkOrderState::Cancelled),

            // Terminal states - no transitions
            (WorkOrderState::Completed, _) => None,
            (WorkOrderState::Cancelled, _) => None,

            // Invalid transitions
            _ => None,
        }
    }

    /// Get all valid actions from the current state
    pub fn valid_actions(current: &WorkOrderState) -> Vec<&'static str> {
        match current {
            WorkOrderState::Draft => vec!["schedule", "cancel"],
            WorkOrderState::Scheduled => vec!["start", "cancel"],
            WorkOrderState::InProgress => vec!["hold", "complete", "cancel"],
            WorkOrderState::OnHold => vec!["resume", "cancel"],
            WorkOrderState::Completed => vec![],
            WorkOrderState::Cancelled => vec![],
        }
    }
}

/// Transition a work order to a new state
///
/// This function:
/// 1. Validates the transition is allowed
/// 2. Updates the work order state
/// 3. Records the transition in audit history
/// 4. Per CLAUDE.md: logs all state changes with user, timestamp, before/after states
pub async fn transition_work_order(
    pool: &ConnectionPool,
    work_order_id: Uuid,
    action: WorkOrderAction,
    user_id: Uuid,
    signature: Option<String>,
) -> VortexResult<WorkOrderState> {
    // Get current work order state
    let current_state_str: Option<String> = sqlx::query_scalar(
        "SELECT state FROM eam_work_orders WHERE id = $1"
    )
        .bind(work_order_id)
        .fetch_optional(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?
        .flatten();

    let current_state = current_state_str
        .as_deref()
        .unwrap_or("draft");

    let current = WorkOrderState::from_str(current_state)
        .ok_or_else(|| VortexError::ValidationFailed(format!("Invalid current state: {}", current_state)))?;

    // Validate transition
    let next_state = WorkOrderStateMachine::next_state(&current, &action)
        .ok_or_else(|| VortexError::ValidationFailed(format!(
            "Invalid transition: cannot {} from state {}",
            action.as_str(),
            current.as_str()
        )))?;

    let now = Utc::now();

    // Build update query based on action
    let mut update_fields = vec![
        ("state", next_state.as_str().to_string()),
        ("updated_at", now.to_rfc3339()),
    ];

    match &action {
        WorkOrderAction::Hold { reason } => {
            update_fields.push(("hold_reason", reason.clone()));
        }
        WorkOrderAction::Cancel { reason } => {
            update_fields.push(("cancel_reason", reason.clone()));
        }
        WorkOrderAction::Start => {
            update_fields.push(("actual_start", now.to_rfc3339()));
        }
        WorkOrderAction::Complete => {
            update_fields.push(("actual_end", now.to_rfc3339()));
        }
        _ => {}
    }

    // Update work order state
    let update_sql = format!(
        "UPDATE eam_work_orders SET state = $1, updated_at = $2, updated_by = $3 {} WHERE id = $4",
        match &action {
            WorkOrderAction::Hold { .. } => ", hold_reason = $5",
            WorkOrderAction::Cancel { .. } => ", cancel_reason = $5",
            WorkOrderAction::Start => ", actual_start = $5",
            WorkOrderAction::Complete => ", actual_end = $5",
            _ => "",
        }
    );

    let query = sqlx::query(&update_sql)
        .bind(next_state.as_str())
        .bind(now)
        .bind(user_id);

    let query = match &action {
        WorkOrderAction::Hold { reason } => query.bind(reason),
        WorkOrderAction::Cancel { reason } => query.bind(reason),
        WorkOrderAction::Start => query.bind(now),
        WorkOrderAction::Complete => query.bind(now),
        _ => query,
    };

    query
        .bind(work_order_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    // Record state transition in history (per CLAUDE.md audit requirements)
    let history_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO eam_work_order_state_history
        (id, work_order_id, from_state, to_state, action, reason, changed_by, changed_at, signature)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#
    )
        .bind(history_id)
        .bind(work_order_id)
        .bind(current.as_str())
        .bind(next_state.as_str())
        .bind(action.as_str())
        .bind(action.reason())
        .bind(user_id)
        .bind(now)
        .bind(signature)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(next_state)
}

/// Check if work order completion requires approval
///
/// Per SESB spec, critical assets require eSig approval
pub async fn requires_completion_approval(
    pool: &ConnectionPool,
    work_order_id: Uuid,
) -> VortexResult<bool> {
    // Check if WO is marked as requiring approval, OR if asset is critical
    let result: Option<(Option<bool>, Option<i32>)> = sqlx::query_as(
        r#"
        SELECT wo.requires_approval, a.criticality_rating
        FROM eam_work_orders wo
        LEFT JOIN eam_assets a ON wo.asset_id = a.id
        WHERE wo.id = $1
        "#
    )
        .bind(work_order_id)
        .fetch_optional(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    match result {
        Some((requires, criticality)) => {
            // Requires approval if explicitly set OR asset is critical (rating >= 4)
            let explicit = requires.unwrap_or(false);
            let critical_asset = criticality.map(|c| c >= 4).unwrap_or(false);
            Ok(explicit || critical_asset)
        }
        None => Err(VortexError::RecordNotFound {
            model: "WorkOrder".to_string(),
            id: RecordId::Uuid(work_order_id),
        }),
    }
}

/// Approve work order completion with electronic signature
///
/// Per CLAUDE.md: eSig required for High criticality assets
pub async fn approve_work_order_completion(
    pool: &ConnectionPool,
    work_order_id: Uuid,
    approver_id: Uuid,
    signature: String,
) -> VortexResult<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE eam_work_orders
        SET approved_by = $1, approved_at = $2, approval_signature = $3, updated_at = $2, updated_by = $1
        WHERE id = $4 AND state = 'completed'
        "#
    )
        .bind(approver_id)
        .bind(now)
        .bind(signature)
        .bind(work_order_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(())
}

/// Inspection Result States
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionState {
    Draft,
    Submitted,
    Approved,
    Rejected,
}

impl InspectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            InspectionState::Draft => "draft",
            InspectionState::Submitted => "submitted",
            InspectionState::Approved => "approved",
            InspectionState::Rejected => "rejected",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "draft" => Some(InspectionState::Draft),
            "submitted" => Some(InspectionState::Submitted),
            "approved" => Some(InspectionState::Approved),
            "rejected" => Some(InspectionState::Rejected),
            _ => None,
        }
    }
}

/// Submit inspection for approval
pub async fn submit_inspection(
    pool: &ConnectionPool,
    inspection_id: Uuid,
    user_id: Uuid,
) -> VortexResult<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE eam_inspection_results
        SET state = 'submitted', updated_at = $1, updated_by = $2
        WHERE id = $3 AND state = 'draft'
        "#
    )
        .bind(now)
        .bind(user_id)
        .bind(inspection_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(())
}

/// Approve inspection with electronic signature
pub async fn approve_inspection(
    pool: &ConnectionPool,
    inspection_id: Uuid,
    approver_id: Uuid,
    signature: String,
) -> VortexResult<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE eam_inspection_results
        SET state = 'approved', approved_by = $1, approved_date = $2, approval_signature = $3,
            updated_at = $2, updated_by = $1
        WHERE id = $4 AND state = 'submitted'
        "#
    )
        .bind(approver_id)
        .bind(now)
        .bind(signature)
        .bind(inspection_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(())
}

/// Reject inspection with reason
pub async fn reject_inspection(
    pool: &ConnectionPool,
    inspection_id: Uuid,
    rejector_id: Uuid,
    reason: String,
) -> VortexResult<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE eam_inspection_results
        SET state = 'rejected', rejection_reason = $1, updated_at = $2, updated_by = $3
        WHERE id = $4 AND state = 'submitted'
        "#
    )
        .bind(reason)
        .bind(now)
        .bind(rejector_id)
        .bind(inspection_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        // Draft -> Scheduled
        assert!(WorkOrderStateMachine::can_transition(
            &WorkOrderState::Draft,
            &WorkOrderAction::Schedule
        ));

        // Scheduled -> InProgress
        assert!(WorkOrderStateMachine::can_transition(
            &WorkOrderState::Scheduled,
            &WorkOrderAction::Start
        ));

        // InProgress -> OnHold
        assert!(WorkOrderStateMachine::can_transition(
            &WorkOrderState::InProgress,
            &WorkOrderAction::Hold { reason: "test".to_string() }
        ));

        // OnHold -> InProgress
        assert!(WorkOrderStateMachine::can_transition(
            &WorkOrderState::OnHold,
            &WorkOrderAction::Resume
        ));

        // InProgress -> Completed
        assert!(WorkOrderStateMachine::can_transition(
            &WorkOrderState::InProgress,
            &WorkOrderAction::Complete
        ));
    }

    #[test]
    fn test_invalid_transitions() {
        // Cannot skip states
        assert!(!WorkOrderStateMachine::can_transition(
            &WorkOrderState::Draft,
            &WorkOrderAction::Complete
        ));

        // Cannot go backwards
        assert!(!WorkOrderStateMachine::can_transition(
            &WorkOrderState::Scheduled,
            &WorkOrderAction::Schedule
        ));

        // Cannot transition from terminal states
        assert!(!WorkOrderStateMachine::can_transition(
            &WorkOrderState::Completed,
            &WorkOrderAction::Start
        ));

        assert!(!WorkOrderStateMachine::can_transition(
            &WorkOrderState::Cancelled,
            &WorkOrderAction::Resume
        ));
    }

    #[test]
    fn test_cancel_from_any_non_terminal() {
        let cancel = WorkOrderAction::Cancel { reason: "test".to_string() };

        assert!(WorkOrderStateMachine::can_transition(&WorkOrderState::Draft, &cancel));
        assert!(WorkOrderStateMachine::can_transition(&WorkOrderState::Scheduled, &cancel));
        assert!(WorkOrderStateMachine::can_transition(&WorkOrderState::InProgress, &cancel));
        assert!(WorkOrderStateMachine::can_transition(&WorkOrderState::OnHold, &cancel));

        // Cannot cancel already cancelled or completed
        assert!(!WorkOrderStateMachine::can_transition(&WorkOrderState::Completed, &cancel));
        assert!(!WorkOrderStateMachine::can_transition(&WorkOrderState::Cancelled, &cancel));
    }

    #[test]
    fn test_terminal_states() {
        assert!(WorkOrderState::Completed.is_terminal());
        assert!(WorkOrderState::Cancelled.is_terminal());
        assert!(!WorkOrderState::Draft.is_terminal());
        assert!(!WorkOrderState::InProgress.is_terminal());
    }
}
