//! Maintenance Models
//!
//! Work orders, maintenance scheduling, and inspection workflows per SESB spec

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_macros::Model;

/// Maintenance Schedule
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_maintenance_schedules", module = "asset_management")]
pub struct MaintenanceSchedule {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required)]
    pub asset_id: Uuid,
    #[vortex(required)]
    pub schedule_name: String,
    #[vortex(required)]
    pub frequency_days: i32,
    pub last_performed: Option<String>,
    pub next_due: Option<String>,
    pub is_active: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Work Order with state machine support
///
/// State transitions:
/// draft → scheduled → in_progress ↔ on_hold → completed
///   ↓         ↓            ↓
/// cancelled ←─────────────────
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_work_orders", module = "asset_management")]
pub struct WorkOrder {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required, unique)]
    pub wo_number: String,
    pub asset_id: Option<Uuid>,
    #[vortex(required)]
    pub title: String,
    pub description: Option<String>,
    // SESB Enhancements
    /// Maintenance type: pm, cm, emergency, inspection, testing, overhaul
    pub maintenance_type: Option<String>,
    /// Priority: 0=Critical, 1=High, 2=Medium, 3=Low
    pub priority: Option<i32>,
    /// Team IDs assigned (JSON array of UUIDs)
    pub team_ids: Option<serde_json::Value>,
    /// Planned duration in hours
    pub planned_duration_hours: Option<f64>,
    // State machine fields
    /// State: draft, scheduled, in_progress, on_hold, completed, cancelled
    pub state: Option<String>,
    /// Reason for hold (when state = on_hold)
    pub hold_reason: Option<String>,
    /// Reason for cancellation (when state = cancelled)
    pub cancel_reason: Option<String>,
    // Scheduling
    pub scheduled_start: Option<DateTime<Utc>>,
    pub scheduled_end: Option<DateTime<Utc>>,
    pub actual_start: Option<DateTime<Utc>>,
    pub actual_end: Option<DateTime<Utc>>,
    // Assignment
    pub assigned_to: Option<Uuid>,
    pub assigned_team_id: Option<Uuid>,
    // Work completion
    /// Findings during work
    pub findings: Option<String>,
    /// Actions taken
    pub actions_taken: Option<String>,
    /// Recommendations for future
    pub recommendations: Option<String>,
    /// Parts used (JSON array)
    pub parts_used: Option<serde_json::Value>,
    // Costs
    pub materials_cost: Option<f64>,
    pub labor_cost: Option<f64>,
    pub total_cost: Option<f64>,
    // Approval workflow
    /// Whether approval is required for completion
    pub requires_approval: Option<bool>,
    pub approved_by: Option<Uuid>,
    pub approved_at: Option<DateTime<Utc>>,
    /// Base64 encoded signature image or hash
    pub approval_signature: Option<String>,
    // Checklist
    /// Checklist template used for this work order
    pub checklist_template_id: Option<Uuid>,
    // References
    pub parent_wo_id: Option<Uuid>,
    pub schedule_id: Option<Uuid>,
    /// Maintenance plan that generated this work order
    pub plan_id: Option<Uuid>,
    // Audit
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
    // Legacy field (kept for compatibility)
    pub status: Option<String>,
}

/// Inspection Result with checklist and approval workflow
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_inspection_results", module = "asset_management")]
pub struct InspectionResult {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    /// Inspection code (auto-generated: INS/2026/00001)
    pub inspection_code: Option<String>,
    #[vortex(required)]
    pub asset_id: Uuid,
    /// Related work order
    pub work_order_id: Option<Uuid>,
    #[vortex(required)]
    pub inspection_date: DateTime<Utc>,
    #[vortex(required)]
    pub inspector_id: Uuid,
    /// Secondary inspector for critical assets
    pub secondary_inspector_id: Option<Uuid>,
    /// Inspection type: routine, detailed, commissioning, post_fault
    pub inspection_type: Option<String>,
    // Checklist items (boolean pass/fail)
    /// Visual inspection check
    pub visual_check: Option<bool>,
    /// Cleanliness check
    pub cleanliness_check: Option<bool>,
    /// Corrosion check
    pub corrosion_check: Option<bool>,
    /// Oil leak check
    pub oil_leak_check: Option<bool>,
    /// Connection/termination check
    pub connection_check: Option<bool>,
    /// Labeling/nameplate check
    pub labeling_check: Option<bool>,
    /// Ventilation check
    pub ventilation_check: Option<bool>,
    /// Security/access check
    pub security_check: Option<bool>,
    // Environmental readings
    pub temperature_c: Option<f64>,
    pub humidity_percent: Option<f64>,
    // Assessment
    pub overall_condition: Option<String>,
    pub condition_score: Option<f64>,
    pub observations: Option<String>,
    /// Defects found description
    pub defects_found: Option<String>,
    /// Requires immediate action
    pub immediate_action_required: Option<bool>,
    /// Action taken on site
    pub immediate_action_taken: Option<String>,
    // Photo attachments (up to 4)
    pub photo_1_id: Option<Uuid>,
    pub photo_1_caption: Option<String>,
    pub photo_2_id: Option<Uuid>,
    pub photo_2_caption: Option<String>,
    pub photo_3_id: Option<Uuid>,
    pub photo_3_caption: Option<String>,
    pub photo_4_id: Option<Uuid>,
    pub photo_4_caption: Option<String>,
    // Approval workflow
    /// State: draft, submitted, approved, rejected
    pub state: Option<String>,
    pub approved_by: Option<Uuid>,
    pub approved_date: Option<DateTime<Utc>>,
    pub approval_signature: Option<String>,
    pub rejection_reason: Option<String>,
    // Audit
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Maintenance Plan
///
/// Defines a recurring maintenance schedule for an asset. Can automatically
/// generate work orders within a planning horizon.
///
/// State: draft → active → done / cancelled
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_maintenance_plans", module = "asset_management")]
pub struct MaintenancePlan {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    /// Auto-generated plan code: PLN/2026/00001
    pub plan_code: Option<String>,
    pub description: Option<String>,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    /// Maintenance type: pm, cm, inspection, testing, overhaul
    #[vortex(required)]
    pub maintenance_type: String,
    /// Priority: 0=Critical, 1=High, 2=Medium, 3=Low
    pub priority: Option<i32>,
    pub planned_duration_hours: Option<f64>,
    pub assigned_to: Option<Uuid>,
    pub checklist_template_id: Option<Uuid>,
    // Schedule configuration
    pub start_date: Option<String>,
    pub next_maintenance_date: Option<String>,
    /// Frequency interval (e.g., 6 for every 6 months)
    pub frequency_interval: Option<i32>,
    /// Frequency unit: day, week, month, year
    pub frequency_unit: Option<String>,
    /// Planning horizon interval
    pub planning_horizon_interval: Option<i32>,
    /// Planning horizon unit: day, week, month, year
    pub planning_horizon_unit: Option<String>,
    /// State: draft, active, done, cancelled
    pub state: Option<String>,
    pub notes: Option<String>,
    pub is_active: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Maintenance Part Line
///
/// Tracks parts used during a work order with quantity and cost tracking.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_maintenance_part_lines", module = "asset_management", multi_tenant = false)]
pub struct MaintenancePartLine {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub work_order_id: Uuid,
    /// Reference to parts catalog
    pub part_id: Option<Uuid>,
    pub sequence: Option<i32>,
    #[vortex(required)]
    pub name: String,
    pub part_number: Option<String>,
    pub quantity: Option<f64>,
    pub unit: Option<String>,
    pub unit_cost: Option<f64>,
    /// Computed: quantity * unit_cost
    pub total_cost: Option<f64>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Work Order State History (for audit trail)
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_work_order_state_history", module = "asset_management", multi_tenant = false)]
pub struct WorkOrderStateHistory {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub work_order_id: Uuid,
    #[vortex(required)]
    pub from_state: String,
    #[vortex(required)]
    pub to_state: String,
    #[vortex(required)]
    pub action: String,
    pub reason: Option<String>,
    #[vortex(required)]
    pub changed_by: Uuid,
    #[vortex(required)]
    pub changed_at: DateTime<Utc>,
    /// Digital signature for critical transitions
    pub signature: Option<String>,
}
