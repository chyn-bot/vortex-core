//! Equipment-Specific Models
//!
//! Extended attributes for specific equipment types per SESB specification

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_macros::Model;

/// Transformer-specific attributes (enhanced per SESB spec)
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_transformers", module = "asset_management", multi_tenant = false)]
pub struct Transformer {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    pub transformer_type: Option<String>,
    pub mva_rating: Option<f64>,
    pub primary_voltage: Option<f64>,
    pub secondary_voltage: Option<f64>,
    pub tertiary_voltage: Option<f64>,
    pub vector_group: Option<String>,
    pub number_of_windings: Option<i32>,
    pub phases: Option<i32>,
    // Tap changer
    pub tap_changer_type: Option<String>,
    pub tap_range: Option<String>,
    pub tap_step_voltage: Option<f64>,
    // Cooling and oil
    pub cooling_type: Option<String>,
    pub oil_type: Option<String>,
    pub oil_volume_liters: Option<f64>,
    // Electrical characteristics
    pub impedance_percent: Option<f64>,
    pub short_circuit_rating: Option<f64>,
    pub total_weight_kg: Option<f64>,
    pub number_of_radiators: Option<i32>,
    // SESB enhancements
    /// Winding material: copper, aluminum
    pub winding_material: Option<String>,
    /// Phase count: 1 or 3
    pub phase_count: Option<i32>,
    /// No-load loss in kW
    pub no_load_loss_kw: Option<f64>,
    /// Load loss in kW
    pub load_loss_kw: Option<f64>,
    // Protection devices
    pub has_buchholz_relay: Option<bool>,
    pub has_pressure_relief: Option<bool>,
    /// Winding Temperature Indicator
    pub has_wti: Option<bool>,
    /// Oil Temperature Indicator
    pub has_oti: Option<bool>,
    /// Magnetic Oil Gauge
    pub has_mog: Option<bool>,
    // DGA monitoring
    /// DGA status: normal, caution, warning, critical
    pub dga_status: Option<String>,
    pub last_dga_date: Option<String>,
    pub dga_baseline_date: Option<String>,
    pub sfra_baseline_date: Option<String>,
}

/// Switch Gear / Circuit Breaker (enhanced per SESB spec)
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_switch_gears", module = "asset_management", multi_tenant = false)]
pub struct SwitchGear {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    pub switchgear_type: Option<String>,
    pub breaker_type: Option<String>,
    pub rated_voltage: Option<f64>,
    pub voltage_class: Option<String>,
    pub rated_current: Option<f64>,
    pub rated_short_circuit_current: Option<f64>,
    pub making_current: Option<f64>,
    pub closing_time_ms: Option<f64>,
    pub opening_time_ms: Option<f64>,
    pub break_time_ms: Option<f64>,
    pub sf6_pressure_rated: Option<f64>,
    pub sf6_pressure_alarm: Option<f64>,
    pub sf6_pressure_trip: Option<f64>,
    pub mechanism_type: Option<String>,
    pub number_of_operations: Option<i32>,
    pub max_operations: Option<i32>,
    pub number_of_poles: Option<i32>,
    // SESB enhancements
    /// SF6 gas volume in kg
    pub sf6_volume_kg: Option<f64>,
    /// Control voltage DC
    pub control_voltage_vdc: Option<f64>,
    /// Motor voltage AC
    pub motor_voltage_vac: Option<f64>,
    /// Current position: open, closed, intermediate
    pub position: Option<String>,
    /// Contact wear percentage (0-100)
    pub contact_wear_percent: Option<f64>,
    pub last_overhaul_date: Option<String>,
}

/// Ring Main Unit (enhanced per SESB spec)
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_ring_main_units", module = "asset_management", multi_tenant = false)]
pub struct RingMainUnit {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    pub rmu_configuration: Option<String>,
    pub number_of_ring_switches: Option<i32>,
    pub number_of_tee_off: Option<i32>,
    pub rmu_type: Option<String>,
    pub insulation_medium: Option<String>,
    pub rated_voltage: Option<f64>,
    pub rated_current: Option<f64>,
    pub short_circuit_rating: Option<f64>,
    pub has_fault_indicator: Option<bool>,
    pub has_load_break_switch: Option<bool>,
    pub has_fuse_switch: Option<bool>,
    pub has_circuit_breaker: Option<bool>,
    pub sf6_pressure_rated: Option<f64>,
    // SESB enhancements
    /// Protection type: fuse, relay, both
    pub protection_type: Option<String>,
    /// Fuse rating in Amperes
    pub fuse_rating_a: Option<f64>,
    /// IP rating (e.g., IP65)
    pub ip_rating: Option<String>,
    /// Dimensions
    pub width_mm: Option<f64>,
    pub height_mm: Option<f64>,
    pub depth_mm: Option<f64>,
    // Unit positions (up to 4 units)
    /// Unit 1 type: ring, tee, cb, vt
    pub unit_1_type: Option<String>,
    /// Unit 1 position: open, closed
    pub unit_1_position: Option<String>,
    pub unit_2_type: Option<String>,
    pub unit_2_position: Option<String>,
    pub unit_3_type: Option<String>,
    pub unit_3_position: Option<String>,
    pub unit_4_type: Option<String>,
    pub unit_4_position: Option<String>,
}

/// Feeder Pillar
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_feeder_pillars", module = "asset_management", multi_tenant = false)]
pub struct FeederPillar {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    pub pillar_type: Option<String>,
    pub voltage_level: Option<f64>,
    pub number_of_ways: Option<i32>,
    pub incoming_cable_size: Option<String>,
    pub outgoing_cable_size: Option<String>,
    pub fuse_rating: Option<f64>,
    pub has_metering: Option<bool>,
    pub enclosure_type: Option<String>,
    pub ip_rating: Option<String>,
}

/// Protection System
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_protection_systems", module = "asset_management", multi_tenant = false)]
pub struct ProtectionSystem {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    pub functional_location_id: Option<Uuid>,
    pub protection_type: Option<String>,
    pub relay_type: Option<String>,
    pub relay_manufacturer: Option<String>,
    pub relay_model: Option<String>,
    pub relay_serial: Option<String>,
    pub protection_functions: Option<serde_json::Value>,
    pub firmware_version: Option<String>,
    pub last_firmware_update: Option<String>,
    pub settings_reference: Option<String>,
    pub last_settings_update: Option<String>,
    pub communication_protocol: Option<String>,
    pub ip_address: Option<String>,
    pub last_test_date: Option<String>,
    pub test_interval_months: Option<i32>,
}

/// SCADA System
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_scada_systems", module = "asset_management", multi_tenant = false)]
pub struct ScadaSystem {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    pub functional_location_id: Option<Uuid>,
    pub scada_type: Option<String>,
    pub rtu_type: Option<String>,
    pub rtu_manufacturer: Option<String>,
    pub rtu_model: Option<String>,
    pub rtu_serial: Option<String>,
    pub communication_protocol: Option<String>,
    pub primary_ip_address: Option<String>,
    pub secondary_ip_address: Option<String>,
    pub port_number: Option<i32>,
    pub number_of_di: Option<i32>,
    pub number_of_do: Option<i32>,
    pub number_of_ai: Option<i32>,
    pub number_of_ao: Option<i32>,
    pub scada_point_prefix: Option<String>,
    pub scada_station_address: Option<i32>,
    pub firmware_version: Option<String>,
}

/// Battery Bank (enhanced per SESB spec)
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_batteries", module = "asset_management", multi_tenant = false)]
pub struct Battery {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    pub functional_location_id: Option<Uuid>,
    pub battery_type: Option<String>,
    pub battery_application: Option<String>,
    pub nominal_voltage: Option<f64>,
    pub capacity_ah: Option<f64>,
    pub number_of_cells: Option<i32>,
    pub cells_per_string: Option<i32>,
    pub number_of_strings: Option<i32>,
    pub charger_manufacturer: Option<String>,
    pub charger_model: Option<String>,
    pub charger_rating: Option<f64>,
    pub charger_redundancy: Option<String>,
    pub last_capacity_test: Option<String>,
    pub last_impedance_test: Option<String>,
    pub capacity_percent: Option<f64>,
    pub float_voltage: Option<f64>,
    pub boost_voltage: Option<f64>,
    pub low_voltage_alarm: Option<f64>,
    pub high_voltage_alarm: Option<f64>,
    // SESB enhancements
    /// State of health percentage (0-100)
    pub state_of_health: Option<f64>,
    /// State of charge percentage (0-100)
    pub state_of_charge: Option<f64>,
    /// Current mode: float, boost, discharge, equalize
    pub current_mode: Option<String>,
    /// Lowest individual cell voltage
    pub lowest_cell_voltage: Option<f64>,
    /// Highest individual cell voltage
    pub highest_cell_voltage: Option<f64>,
}

// ============================================================================
// NEW EQUIPMENT TYPES PER SESB SPEC
// ============================================================================

/// Current/Voltage Transformer (CT/VT/CVT)
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_current_voltage_transformers", module = "asset_management", multi_tenant = false)]
pub struct CurrentVoltageTransformer {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    /// Device type: ct, vt, cvt (combined)
    pub device_type: Option<String>,
    /// Ratio primary value (e.g., 400 for 400/5 CT)
    pub ratio_primary: Option<f64>,
    /// Ratio secondary value (e.g., 5 for 400/5 CT)
    pub ratio_secondary: Option<f64>,
    /// Accuracy class (e.g., 0.2, 0.5, 1.0, 5P)
    pub accuracy_class: Option<String>,
    /// Burden in VA
    pub burden_va: Option<f64>,
    /// Rated voltage in kV
    pub rated_voltage_kv: Option<f64>,
    /// Insulation class
    pub insulation_class: Option<String>,
    /// Number of cores/windings
    pub number_of_cores: Option<i32>,
    /// Core 1 class (for multi-core CTs)
    pub core_1_class: Option<String>,
    pub core_1_burden_va: Option<f64>,
    pub core_2_class: Option<String>,
    pub core_2_burden_va: Option<f64>,
    pub core_3_class: Option<String>,
    pub core_3_burden_va: Option<f64>,
    /// Thermal rating factor
    pub thermal_rating_factor: Option<f64>,
    /// Short time thermal current in kA
    pub short_time_current_ka: Option<f64>,
    /// Last ratio test date
    pub last_ratio_test: Option<String>,
    /// Last polarity test date
    pub last_polarity_test: Option<String>,
}

/// Surge Arrester / Lightning Arrester
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_surge_arresters", module = "asset_management", multi_tenant = false)]
pub struct SurgeArrester {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    /// Arrester type: station, distribution, line
    pub arrester_type: Option<String>,
    /// Maximum Continuous Operating Voltage in kV
    pub mcov_kv: Option<f64>,
    /// Rated voltage in kV
    pub rated_voltage_kv: Option<f64>,
    /// Discharge class: 1, 2, 3, 4, 5
    pub discharge_class: Option<String>,
    /// Nominal discharge current in kA
    pub nominal_discharge_current_ka: Option<f64>,
    /// Leakage current in mA
    pub leakage_current_ma: Option<f64>,
    /// Reference voltage in kV
    pub reference_voltage_kv: Option<f64>,
    /// Energy absorption capability in kJ/kV
    pub energy_capability_kj_kv: Option<f64>,
    /// Housing material: porcelain, polymer
    pub housing_material: Option<String>,
    /// Has surge counter
    pub has_surge_counter: Option<bool>,
    /// Surge counter reading
    pub surge_counter_reading: Option<i32>,
    /// Last leakage current test
    pub last_leakage_test: Option<String>,
}

/// Cable
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_cables", module = "asset_management", multi_tenant = false)]
pub struct Cable {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    /// Cable type: xlpe, pilc, epr, pvc
    pub cable_type: Option<String>,
    /// Voltage rating in kV
    pub voltage_rating_kv: Option<f64>,
    /// Conductor material: copper, aluminum
    pub conductor_material: Option<String>,
    /// Conductor size in mm²
    pub conductor_size_mm2: Option<f64>,
    /// Number of cores
    pub number_of_cores: Option<i32>,
    /// Length in meters
    pub length_m: Option<f64>,
    /// From equipment ID
    pub from_equipment_id: Option<Uuid>,
    /// To equipment ID
    pub to_equipment_id: Option<Uuid>,
    /// From location description
    pub from_location: Option<String>,
    /// To location description
    pub to_location: Option<String>,
    /// Installation type: direct_buried, duct, tray, aerial
    pub installation_type: Option<String>,
    /// Rated current in Amperes
    pub rated_current_a: Option<f64>,
    /// Insulation resistance in MOhm
    pub insulation_resistance_mohm: Option<f64>,
    /// Last insulation test date
    pub last_insulation_test: Option<String>,
    /// Last VLF test date
    pub last_vlf_test: Option<String>,
}

/// Busbar
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_busbars", module = "asset_management", multi_tenant = false)]
pub struct Busbar {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    /// Busbar type: rigid, flexible, gis
    pub busbar_type: Option<String>,
    /// Material: copper, aluminum
    pub material: Option<String>,
    /// Rated current in Amperes
    pub rated_current_a: Option<f64>,
    /// Rated voltage in kV
    pub rated_voltage_kv: Option<f64>,
    /// Short circuit rating in kA
    pub short_circuit_rating_ka: Option<f64>,
    /// Cross section dimensions (e.g., "100x10" mm)
    pub cross_section: Option<String>,
    /// Length in meters
    pub length_m: Option<f64>,
    /// Number of conductors per phase
    pub conductors_per_phase: Option<i32>,
    /// Coating type: bare, silver, tin
    pub coating: Option<String>,
    /// Configuration: single, double
    pub configuration: Option<String>,
    /// Last thermal scan date
    pub last_thermal_scan: Option<String>,
}

/// Isolator / Disconnector
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_isolators", module = "asset_management", multi_tenant = false)]
pub struct Isolator {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    /// Isolator type: line, bus, transfer, earthing
    pub isolator_type: Option<String>,
    /// Rated voltage in kV
    pub rated_voltage_kv: Option<f64>,
    /// Rated current in Amperes
    pub rated_current_a: Option<f64>,
    /// Short circuit rating in kA
    pub short_circuit_rating_ka: Option<f64>,
    /// Mechanism type: manual, motor, pneumatic
    pub mechanism_type: Option<String>,
    /// Current position: open, closed
    pub position: Option<String>,
    /// Has earth switch
    pub has_earth_switch: Option<bool>,
    /// Earth switch position
    pub earth_switch_position: Option<String>,
    /// Number of poles
    pub number_of_poles: Option<i32>,
    /// Interlock type
    pub interlock_type: Option<String>,
    /// Total operations count
    pub operation_count: Option<i32>,
    /// Last maintenance date
    pub last_maintenance: Option<String>,
}

/// Earthing System
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_earthing_systems", module = "asset_management", multi_tenant = false)]
pub struct EarthingSystem {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, unique)]
    pub asset_id: Uuid,
    /// Earth type: grid, rod, plate, ring
    pub earth_type: Option<String>,
    /// Earth resistance in Ohms
    pub earth_resistance_ohm: Option<f64>,
    /// Target resistance in Ohms
    pub target_resistance_ohm: Option<f64>,
    /// Grid material: copper, steel, galvanized
    pub material: Option<String>,
    /// Conductor size in mm²
    pub conductor_size_mm2: Option<f64>,
    /// Number of earth rods
    pub number_of_rods: Option<i32>,
    /// Rod length in meters
    pub rod_length_m: Option<f64>,
    /// Grid depth in meters
    pub grid_depth_m: Option<f64>,
    /// Grid area in m²
    pub grid_area_m2: Option<f64>,
    /// Soil resistivity in Ohm-m
    pub soil_resistivity_ohm_m: Option<f64>,
    /// Step potential in Volts
    pub step_potential_v: Option<f64>,
    /// Touch potential in Volts
    pub touch_potential_v: Option<f64>,
    /// Last earth resistance test
    pub last_resistance_test: Option<String>,
    /// Last step/touch potential test
    pub last_potential_test: Option<String>,
}
