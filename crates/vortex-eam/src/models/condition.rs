//! Condition Monitoring Models
//!
//! Specialized test models for condition-based monitoring per SESB spec

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_macros::Model;

/// Condition Monitoring Record (generic time-series data)
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_condition_monitoring", module = "asset_management")]
pub struct ConditionMonitoringRecord {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    #[vortex(required)]
    pub parameter_name: String,
    #[vortex(required, indexed)]
    pub measurement_date: DateTime<Utc>,
    pub value_numeric: Option<f64>,
    pub value_text: Option<String>,
    pub unit: Option<String>,
    pub status: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}

/// Asset Health Index
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_asset_health_indices", module = "asset_management", multi_tenant = false)]
pub struct AssetHealthIndex {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    #[vortex(required, indexed)]
    pub calculated_at: DateTime<Utc>,
    #[vortex(required)]
    pub health_index: f64,
    pub health_category: Option<String>,
    pub probability_of_failure: Option<f64>,
    pub risk_score: Option<f64>,
    pub recommended_action: Option<String>,
    pub calculation_method: Option<String>,
}

// ============================================================================
// SPECIALIZED CONDITION MONITORING MODELS PER SESB SPEC
// ============================================================================

/// Dissolved Gas Analysis (DGA) for transformer oil
/// Used for fault detection in oil-filled transformers
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_dga_analyses", module = "asset_management", multi_tenant = false)]
pub struct DgaAnalysis {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    #[vortex(required, indexed)]
    pub sample_date: DateTime<Utc>,
    pub lab_reference: Option<String>,
    // Key fault gases (all in ppm)
    /// Hydrogen (H2) - key indicator for PD and arcing
    pub hydrogen_h2_ppm: Option<f64>,
    /// Methane (CH4) - thermal decomposition
    pub methane_ch4_ppm: Option<f64>,
    /// Ethane (C2H6) - low temperature thermal fault
    pub ethane_c2h6_ppm: Option<f64>,
    /// Ethylene (C2H4) - high temperature thermal fault
    pub ethylene_c2h4_ppm: Option<f64>,
    /// Acetylene (C2H2) - arcing fault indicator
    pub acetylene_c2h2_ppm: Option<f64>,
    /// Carbon Monoxide (CO) - cellulose degradation
    pub carbon_monoxide_co_ppm: Option<f64>,
    /// Carbon Dioxide (CO2) - cellulose degradation
    pub carbon_dioxide_co2_ppm: Option<f64>,
    /// Oxygen (O2)
    pub oxygen_o2_ppm: Option<f64>,
    /// Nitrogen (N2)
    pub nitrogen_n2_ppm: Option<f64>,
    // Calculated values
    /// Total Combustible Gas (TCG) = H2 + CH4 + C2H6 + C2H4 + C2H2 + CO
    pub total_combustible_gas_ppm: Option<f64>,
    /// Fault type from Duval Triangle or other method
    pub fault_type: Option<String>,
    /// Assessment status: normal, caution, warning, critical
    pub status: Option<String>,
    /// Assessment method: duval_triangle, rogers_ratio, ieee_c57_104
    pub assessment_method: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}

/// Oil Quality Test for transformer insulating oil
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_oil_quality_tests", module = "asset_management", multi_tenant = false)]
pub struct OilQualityTest {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    #[vortex(required, indexed)]
    pub test_date: DateTime<Utc>,
    pub lab_reference: Option<String>,
    /// Breakdown Voltage (BDV) in kV - dielectric strength
    pub bdv_kv: Option<f64>,
    /// Moisture content in ppm
    pub moisture_ppm: Option<f64>,
    /// Acidity (neutralization number) in mg KOH/g
    pub acidity_mg_koh: Option<f64>,
    /// Interfacial Tension in mN/m (oil-water interface)
    pub ift_mn_m: Option<f64>,
    /// Dissipation Factor (Tan Delta) at 90°C
    pub tan_delta: Option<f64>,
    /// Color (ASTM scale 0-8)
    pub color: Option<f64>,
    /// Specific gravity
    pub specific_gravity: Option<f64>,
    /// Flash point in °C
    pub flash_point_c: Option<f64>,
    /// Pour point in °C
    pub pour_point_c: Option<f64>,
    /// Viscosity at 40°C in cSt
    pub viscosity_40c_cst: Option<f64>,
    /// PCB content in ppm
    pub pcb_ppm: Option<f64>,
    /// Furan content (2-FAL) in ppb - paper degradation indicator
    pub furan_2fal_ppb: Option<f64>,
    /// Overall status: good, acceptable, marginal, poor
    pub status: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}

/// Thermal Imaging / Infrared Scan Results
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_thermal_imaging", module = "asset_management", multi_tenant = false)]
pub struct ThermalImaging {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    #[vortex(required, indexed)]
    pub scan_date: DateTime<Utc>,
    /// Component/location being scanned
    pub component_location: Option<String>,
    /// Ambient temperature in °C
    pub ambient_temp_c: Option<f64>,
    /// Load percentage at time of scan
    pub load_percent: Option<f64>,
    /// Maximum temperature detected in °C
    pub max_temp_c: Option<f64>,
    /// Reference temperature (similar component) in °C
    pub reference_temp_c: Option<f64>,
    /// Hot spot location description
    pub hot_spot_location: Option<String>,
    /// Delta T (temperature rise above reference) in °C
    pub delta_t_c: Option<f64>,
    /// Severity: normal, attention, intermediate, serious, critical
    pub severity: Option<String>,
    /// Emissivity setting used
    pub emissivity: Option<f64>,
    /// Distance to target in meters
    pub distance_m: Option<f64>,
    /// Thermal image file reference
    pub thermal_image_id: Option<Uuid>,
    /// Visual image file reference
    pub visual_image_id: Option<Uuid>,
    pub recommended_action: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}

/// Partial Discharge (PD) Test Results
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_partial_discharge_tests", module = "asset_management", multi_tenant = false)]
pub struct PartialDischarge {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    #[vortex(required, indexed)]
    pub test_date: DateTime<Utc>,
    /// Test method: online, offline, acoustic, uhf, hfct
    pub test_method: Option<String>,
    /// Test voltage in kV
    pub test_voltage_kv: Option<f64>,
    /// Maximum PD magnitude in pC (picocoulombs)
    pub magnitude_pc: Option<f64>,
    /// PD inception voltage in kV
    pub inception_voltage_kv: Option<f64>,
    /// PD extinction voltage in kV
    pub extinction_voltage_kv: Option<f64>,
    /// Repetition rate in pulses per second
    pub repetition_rate_pps: Option<f64>,
    /// PD pattern type: surface, void, corona, floating
    pub pattern: Option<String>,
    /// Phase angle of maximum activity (degrees)
    pub phase_angle_deg: Option<f64>,
    /// Location of PD source (if determined)
    pub pd_location: Option<String>,
    /// Background noise level in pC
    pub background_noise_pc: Option<f64>,
    /// Status: pass, fail, marginal
    pub status: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}

/// Insulation Resistance (IR) / Megger Test Results
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_insulation_resistance_tests", module = "asset_management", multi_tenant = false)]
pub struct InsulationResistance {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    #[vortex(required, indexed)]
    pub test_date: DateTime<Utc>,
    /// Test configuration (e.g., HV-LV, HV-E, LV-E for transformers)
    pub test_configuration: Option<String>,
    /// Test voltage in V
    pub test_voltage_v: Option<f64>,
    /// Temperature at test in °C
    pub temperature_c: Option<f64>,
    /// Humidity at test in %
    pub humidity_percent: Option<f64>,
    /// 30-second IR reading in MOhm (for DAR calculation)
    pub ir_30s_mohm: Option<f64>,
    /// 1-minute IR reading in MOhm
    pub ir_1min_mohm: Option<f64>,
    /// 10-minute IR reading in MOhm
    pub ir_10min_mohm: Option<f64>,
    /// Polarization Index (PI) = IR_10min / IR_1min
    /// Computed field, but stored for reference
    pub polarization_index: Option<f64>,
    /// Dielectric Absorption Ratio (DAR) = IR_1min / IR_30sec
    pub dielectric_absorption_ratio: Option<f64>,
    /// IR value corrected to 20°C in MOhm
    pub ir_corrected_20c_mohm: Option<f64>,
    /// Minimum acceptable IR in MOhm
    pub minimum_ir_mohm: Option<f64>,
    /// Status: pass, fail, marginal
    pub status: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}

/// SF6 Gas Analysis for gas-insulated switchgear and circuit breakers
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_sf6_analyses", module = "asset_management", multi_tenant = false)]
pub struct Sf6Analysis {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    #[vortex(required, indexed)]
    pub test_date: DateTime<Utc>,
    pub lab_reference: Option<String>,
    /// SF6 purity in percent
    pub sf6_purity_percent: Option<f64>,
    /// Moisture content in ppm
    pub sf6_moisture_ppm: Option<f64>,
    /// SO2 content in ppm (decomposition product)
    pub sf6_so2_ppm: Option<f64>,
    /// Gas pressure in bar
    pub sf6_pressure_bar: Option<f64>,
    /// Dew point in °C
    pub sf6_dew_point_c: Option<f64>,
    /// Status: normal, caution, warning, critical
    pub status: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}

/// Contact Resistance and Timing Test for circuit breakers
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_contact_timing_tests", module = "asset_management", multi_tenant = false)]
pub struct ContactTimingTest {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    #[vortex(required, indexed)]
    pub test_date: DateTime<Utc>,
    pub lab_reference: Option<String>,
    /// Contact resistance in micro-ohm
    pub contact_resistance_micro_ohm: Option<f64>,
    /// Closing time in milliseconds
    pub closing_time_ms: Option<f64>,
    /// Opening time in milliseconds
    pub opening_time_ms: Option<f64>,
    /// Close-open time in milliseconds
    pub close_open_time_ms: Option<f64>,
    /// Reclose time in milliseconds
    pub reclose_time_ms: Option<f64>,
    /// Simultaneity of phases in milliseconds
    pub simultaneity_ms: Option<f64>,
    /// Status: pass, fail, marginal
    pub status: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}

/// Battery Discharge Test for station battery banks
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_battery_discharge_tests", module = "asset_management", multi_tenant = false)]
pub struct BatteryDischargeTest {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    #[vortex(required, indexed)]
    pub test_date: DateTime<Utc>,
    pub lab_reference: Option<String>,
    /// Remaining capacity as percentage of rated
    pub capacity_percent: Option<f64>,
    /// Discharge duration in hours
    pub discharge_time_hours: Option<f64>,
    /// Internal resistance in milli-ohm
    pub internal_resistance_mohm: Option<f64>,
    /// Float voltage in V
    pub float_voltage_v: Option<f64>,
    /// Equalize voltage in V
    pub equalize_voltage_v: Option<f64>,
    /// Electrolyte specific gravity
    pub specific_gravity: Option<f64>,
    /// Electrolyte temperature in °C
    pub electrolyte_temp_c: Option<f64>,
    /// Status: pass, fail, marginal
    pub status: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}
