//! EAM Business Logic Services
//!
//! Services for condition monitoring, workflows, health index, QR codes, sequences,
//! checklists, and maintenance plans.

pub mod seed;
pub mod condition;
pub mod workflow;
pub mod health_index;
pub mod qr_code;
pub mod sequence;
pub mod checklist;
pub mod plan;

// Re-export commonly used functions
pub use seed::seed_eam_defaults;

// Condition monitoring
pub use condition::{
    classify_dga_fault,
    assess_dga_status,
    compute_tcg,
    DgaFaultType,
    DgaStatus,
};

// Workflow state machine
pub use workflow::{
    WorkOrderState,
    WorkOrderAction,
    WorkOrderStateMachine,
    transition_work_order,
    requires_completion_approval,
    approve_work_order_completion,
    InspectionState,
    submit_inspection,
    approve_inspection,
    reject_inspection,
};

// Health index computation
pub use health_index::{
    compute as compute_health_index,
    compute_from_scores as compute_health_index_from_scores,
    categorize as categorize_health_index,
    probability_of_failure,
    compute_risk_score,
    HealthCategory,
};

// QR code generation
pub use qr_code::{
    generate_code_string as generate_qr_code_string,
    generate_equipment_qr,
    parse_code_string as parse_qr_code_string,
    generate_image as generate_qr_image,
    EntityType as QrEntityType,
};

// Sequence generation
pub use sequence::{
    next_equipment_code,
    next_component_code,
    next_part_code,
    next_maintenance_code,
    next_inspection_code,
    SequenceType,
};

// Checklist service
pub use checklist::{
    generate_checklist_lines,
    compute_checklist_progress,
    compute_checklist_score,
    score_checklist_line,
    ChecklistProgress,
    ChecklistScore,
    ChecklistResult,
};

// Maintenance plan service
pub use plan::{
    activate_plan,
    cancel_plan,
    generate_planned_orders,
    PlanState,
};
