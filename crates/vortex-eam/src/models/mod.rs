//! EAM Models
//!
//! Database models for Enterprise Asset Management with SESB specification parity.
//!
//! ## Hierarchy (8 levels)
//! - **L0 Region**: Parent of Sites, division (transmission/distribution)
//! - **L1 Site**: Physical location containing substations
//! - **L2 Substation**: Electrical substation within a site
//! - **L3 Bay**: Functional unit within substation (replaces FunctionalLocation)
//! - **L4 Asset**: Equipment (transformers, switchgear, etc.)
//! - **L5 Component**: Sub-components of assets
//! - **L6-7 Part**: Replaceable parts with self-referencing hierarchy
//!
//! ## Configuration
//! - Manufacturer, VoltageLevel, UnitType, AssetCategory, AssetStatus
//!
//! ## Equipment Types
//! - Original: Transformer, SwitchGear, RingMainUnit, FeederPillar, ProtectionSystem, ScadaSystem, Battery
//! - New: CurrentVoltageTransformer, SurgeArrester, Cable, Busbar, Isolator, EarthingSystem
//!
//! ## Transmission
//! - TransmissionLine: Overhead power lines connecting substations
//! - TransmissionTower: Structures along a line with GPS coordinates
//!
//! ## Condition Monitoring
//! - Generic: ConditionMonitoringRecord, AssetHealthIndex
//! - Specialized: DgaAnalysis, OilQualityTest, ThermalImaging, PartialDischarge, InsulationResistance
//! - Specialized: Sf6Analysis, ContactTimingTest, BatteryDischargeTest
//!
//! ## Maintenance
//! - MaintenanceSchedule, WorkOrder (with state machine), InspectionResult (with approval workflow)
//! - WorkOrderStateHistory (immutable audit trail)
//! - MaintenancePlan (recurring schedule with work order generation)
//! - MaintenancePartLine (parts tracking on work orders)
//!
//! ## Checklists
//! - ChecklistTemplate, ChecklistTemplateItem, ChecklistLine (6 input types with scoring)

pub mod configuration;
pub mod hierarchy;
pub mod equipment;
pub mod maintenance;
pub mod condition;
pub mod checklist;
pub mod transmission;

pub use configuration::*;
pub use hierarchy::*;
pub use equipment::*;
pub use maintenance::*;
pub use condition::*;
pub use checklist::*;
pub use transmission::*;
