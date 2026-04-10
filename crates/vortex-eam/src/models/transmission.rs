//! Transmission Models
//!
//! Models for the transmission network: Transmission Lines and Towers.
//! These extend the hierarchy to support overhead line assets in addition
//! to substation-based distribution equipment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_macros::Model;

/// Transmission Line - overhead power line connecting substations
///
/// A transmission line belongs to a region (transmission division) and
/// connects two substations. It contains towers along its route.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_transmission_lines", module = "asset_management")]
pub struct TransmissionLine {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required, unique)]
    pub code: String,
    #[vortex(required)]
    pub name: String,

    // Hierarchy
    /// Parent region (must be transmission division)
    #[vortex(required, indexed)]
    pub region_id: Uuid,
    /// Voltage level of this line
    pub voltage_level_id: Option<Uuid>,

    // Route
    /// Origin substation
    pub from_substation_id: Option<Uuid>,
    /// Destination substation
    pub to_substation_id: Option<Uuid>,
    /// Total line length in km
    pub line_length_km: Option<f64>,

    // Conductor specifications
    /// Conductor type: acsr, acar, aaac, aac, accc, htls, opgw
    pub conductor_type: Option<String>,
    /// Conductor cross-section area in mm²
    pub conductor_size_mm2: Option<f64>,
    /// Number of circuits on this line
    pub number_of_circuits: Option<i32>,
    /// Earth/shield wire type
    pub earth_wire_type: Option<String>,
    /// Thermal rated current in Amperes
    pub rated_current_a: Option<f64>,
    /// Maximum conductor sag in metres
    pub max_sag_m: Option<f64>,

    // Lifecycle
    /// State: planning, construction, operational, maintenance, decommissioned
    pub state: Option<String>,
    pub commissioning_date: Option<String>,
    pub design_life_years: Option<i32>,

    /// Ownership: sesb, ipp, shared
    pub ownership: Option<String>,

    pub notes: Option<String>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Transmission Tower - structure supporting conductors along a line
///
/// Each tower belongs to a transmission line and has a sequential number.
/// Towers have GPS coordinates and can host equipment (e.g., line traps).
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_transmission_towers", module = "asset_management")]
pub struct TransmissionTower {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required, unique)]
    pub code: String,
    #[vortex(required)]
    pub name: String,

    // Hierarchy
    /// Parent transmission line
    #[vortex(required, indexed)]
    pub transmission_line_id: Uuid,
    /// Sequential tower number along the line
    pub tower_number: Option<i32>,

    // Classification
    /// Tower type: lattice_steel, tubular_steel, wood_pole, concrete_pole,
    /// monopole, h_frame, guyed_v, self_supporting
    pub tower_type: Option<String>,
    /// Tower function: suspension, tension, angle, dead_end, transposition, junction
    pub tower_function: Option<String>,

    // Physical dimensions
    pub height_m: Option<f64>,
    pub base_width_m: Option<f64>,
    pub weight_kg: Option<f64>,
    pub foundation_type: Option<String>,

    // Span
    /// Distance to next tower in metres
    pub span_to_next_m: Option<f64>,
    /// Distance to previous tower in metres
    pub span_to_previous_m: Option<f64>,

    // GPS coordinates
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub elevation_m: Option<f64>,
    /// Minimum ground clearance in metres
    pub ground_clearance_m: Option<f64>,
    /// Right of way width in metres
    pub right_of_way_m: Option<f64>,

    // Electrical
    pub phase_configuration: Option<String>,
    /// Insulator type: glass, porcelain, composite
    pub insulator_type: Option<String>,
    /// Number of insulator discs per string
    pub insulator_count: Option<i32>,
    pub earth_wire_attached: Option<bool>,
    pub aviation_marking: Option<bool>,

    // Status and condition
    /// Operational status: operational, standby, out_of_service, under_repair, decommissioned
    pub operational_status: Option<String>,
    /// Condition: excellent, good, fair, poor, critical
    pub condition_status: Option<String>,
    /// Health index (0-100), computed from condition * operational factor
    pub health_index: Option<f64>,

    // Inspection
    pub last_inspection_date: Option<String>,
    pub next_inspection_date: Option<String>,

    pub notes: Option<String>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}
