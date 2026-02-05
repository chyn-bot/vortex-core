//! # Vortex EAM - Enterprise Asset Management Module
//!
//! SESB Specification Parity Implementation with 8-level asset hierarchy.
//!
//! ## Asset Hierarchy (8 Levels)
//!
//! ```text
//! Region (L0) - Division (Transmission/Distribution)
//! └── Site (L1) - Physical location
//!     └── Substation (L2) - Electrical infrastructure
//!         └── Bay (L3) - Functional unit (feeder, transformer, bus coupler)
//!             └── Asset (L4) - Equipment instance
//!                 └── Component (L5) - Sub-component
//!                     └── Part (L6-7) - Replaceable parts (with sub-parts)
//! ```
//!
//! ## Equipment Types
//!
//! - Power Transformers (with DGA monitoring)
//! - Switch Gear / Circuit Breakers
//! - Ring Main Units (RMU)
//! - Current/Voltage Transformers (CT/VT/CVT)
//! - Surge Arresters
//! - Cables
//! - Busbars
//! - Isolators / Disconnectors
//! - Earthing Systems
//! - Protection Systems
//! - SCADA Systems
//! - Battery Banks
//!
//! ## Condition Monitoring
//!
//! - Dissolved Gas Analysis (DGA) with Duval Triangle classification
//! - Oil Quality Tests
//! - Thermal Imaging
//! - Partial Discharge Tests
//! - Insulation Resistance Tests
//!
//! ## Maintenance Workflows
//!
//! - Work Orders with state machine (draft → scheduled → in_progress → completed)
//! - Inspection Results with approval workflow
//! - Audit trail for state transitions (per CLAUDE.md compliance)
//! - Electronic signature support for critical assets

pub mod models;
pub mod module;
pub mod handlers;
pub mod services;

pub use module::EamModule;

// Re-export configuration models
pub use models::configuration::{Manufacturer, VoltageLevel, UnitType, AssetCategory, AssetStatus};

// Re-export hierarchy models (8-level)
pub use models::hierarchy::{
    Region, Site, Substation, Bay,
    FunctionalLocation, // Legacy
    Asset, AssetAttribute, Component, Part,
};

// Re-export equipment models (original)
pub use models::equipment::{
    Transformer, SwitchGear, RingMainUnit, FeederPillar,
    ProtectionSystem, ScadaSystem, Battery,
};

// Re-export equipment models (new per SESB)
pub use models::equipment::{
    CurrentVoltageTransformer, SurgeArrester, Cable, Busbar, Isolator, EarthingSystem,
};

// Re-export maintenance models
pub use models::maintenance::{
    MaintenanceSchedule, WorkOrder, WorkOrderStateHistory, InspectionResult,
    MaintenancePlan, MaintenancePartLine,
};

// Re-export checklist models
pub use models::checklist::{
    ChecklistTemplate, ChecklistTemplateItem, ChecklistLine,
};

// Re-export condition monitoring models (generic)
pub use models::condition::{ConditionMonitoringRecord, AssetHealthIndex};

// Re-export condition monitoring models (specialized)
pub use models::condition::{
    DgaAnalysis, OilQualityTest, ThermalImaging, PartialDischarge, InsulationResistance,
    Sf6Analysis, ContactTimingTest, BatteryDischargeTest,
};

// Re-export commonly used services
pub use services::{
    // Seed
    seed_eam_defaults,
    // Condition monitoring
    classify_dga_fault, assess_dga_status, compute_tcg, DgaFaultType, DgaStatus,
    // Workflow
    WorkOrderState, WorkOrderAction, WorkOrderStateMachine,
    transition_work_order, InspectionState,
    // Health index
    compute_health_index, categorize_health_index, probability_of_failure, HealthCategory,
    // QR code
    generate_qr_code_string, generate_equipment_qr, QrEntityType,
    // Sequences
    next_equipment_code, next_maintenance_code, next_inspection_code, SequenceType,
    // Checklists
    generate_checklist_lines, compute_checklist_progress, compute_checklist_score,
    score_checklist_line, ChecklistProgress, ChecklistScore, ChecklistResult,
    // Maintenance plans
    activate_plan, cancel_plan, generate_planned_orders, PlanState,
};
