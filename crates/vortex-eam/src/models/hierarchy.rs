//! Hierarchy Models
//!
//! 8-level asset hierarchy per SESB specification:
//! Region (L0) → Site (L1) → Substation (L2) → Bay (L3) → Asset (L4) → Component (L5) → Part (L6-7)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_macros::Model;

/// Region (L0) - Top level of hierarchy, parent of Sites
/// Represents transmission/distribution division regions
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_regions", module = "asset_management")]
pub struct Region {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required, indexed)]
    pub code: String,
    #[vortex(required)]
    pub name: String,
    pub short_name: Option<String>,
    pub description: Option<String>,
    /// Division type: transmission or distribution
    pub division: Option<String>,
    /// Region manager user ID
    pub manager_id: Option<Uuid>,
    pub display_order: Option<i32>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Site (L1) - Pencawang/Location containing substations
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_sites", module = "asset_management")]
pub struct Site {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    /// Parent region (L0)
    pub region_id: Option<Uuid>,
    #[vortex(required, indexed)]
    pub code: String,
    #[vortex(required)]
    pub name: String,
    pub short_name: Option<String>,
    pub description: Option<String>,
    pub address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub site_type: Option<String>,
    pub voltage_levels: Option<serde_json::Value>,
    pub commissioning_date: Option<String>,
    pub ownership: Option<String>,
    pub operator: Option<String>,
    pub busbar_configuration: Option<String>,
    pub feeder_count: Option<i32>,
    pub status: Option<String>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Substation (L2) - Electrical substation within a Site
/// Contains bays and represents the electrical infrastructure
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_substations", module = "asset_management")]
pub struct Substation {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required, indexed)]
    pub site_id: Uuid,
    #[vortex(required, indexed)]
    pub code: String,
    #[vortex(required)]
    pub name: String,
    pub short_name: Option<String>,
    pub description: Option<String>,
    /// Type: indoor_gis, outdoor_ais, hybrid, mobile
    pub substation_type: Option<String>,
    /// Busbar configuration: single, double, ring, breaker_and_half, etc.
    pub busbar_configuration: Option<String>,
    /// Ownership: sesb, tnb, ippp, customer
    pub ownership: Option<String>,
    pub design_life_years: Option<i32>,
    pub commissioning_date: Option<String>,
    pub voltage_level_id: Option<Uuid>,
    pub qr_code: Option<String>,
    pub qr_code_generated_at: Option<DateTime<Utc>>,
    pub display_order: Option<i32>,
    pub status: Option<String>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Bay (L3) - Replaces FunctionalLocation, represents a bay within a substation
/// A bay is a functional unit containing equipment (breakers, CTs, VTs, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_bays", module = "asset_management")]
pub struct Bay {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required, indexed)]
    pub substation_id: Uuid,
    #[vortex(required)]
    pub unit_type_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub voltage_level_id: Option<Uuid>,
    #[vortex(required, indexed)]
    pub code: String,
    #[vortex(required)]
    pub name: String,
    pub short_name: Option<String>,
    pub description: Option<String>,
    /// Bay type: feeder, transformer, bus_coupler, bus_section, capacitor, reactor
    pub bay_type: Option<String>,
    /// Feeder name for feeder bays
    pub feeder_name: Option<String>,
    /// Rated current in Amperes
    pub rated_current_a: Option<f64>,
    /// SCADA point group reference
    pub scada_point_group: Option<String>,
    pub sld_reference: Option<String>,
    pub qr_code: Option<String>,
    pub qr_code_generated_at: Option<DateTime<Utc>>,
    pub display_order: Option<i32>,
    pub status: Option<String>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Functional Location (Legacy - PPU, SSU 33kV, SSU 11kV, PP, PE)
/// @deprecated Use Bay instead for new implementations
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_functional_locations", module = "asset_management")]
pub struct FunctionalLocation {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required, indexed)]
    pub site_id: Uuid,
    #[vortex(required)]
    pub unit_type_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub voltage_level_id: Option<Uuid>,
    #[vortex(required)]
    pub code: String,
    #[vortex(required)]
    pub name: String,
    pub short_name: Option<String>,
    pub description: Option<String>,
    pub sld_reference: Option<String>,
    pub scada_point_group: Option<String>,
    pub qr_code: Option<String>,
    pub qr_code_generated_at: Option<DateTime<Utc>>,
    pub display_order: Option<i32>,
    pub status: Option<String>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Asset (L4) - Equipment within a Bay
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_assets", module = "asset_management")]
pub struct Asset {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    /// Bay reference (L3) - for distribution equipment
    pub bay_id: Option<Uuid>,
    /// Tower reference - for transmission equipment (alternative to bay_id)
    pub tower_id: Option<Uuid>,
    /// Legacy functional location reference (deprecated, for migration compatibility)
    pub functional_location_id: Option<Uuid>,
    #[vortex(required)]
    pub category_id: Uuid,
    pub status_id: Option<Uuid>,
    pub voltage_level_id: Option<Uuid>,
    /// Manufacturer reference (FK to eam_manufacturers)
    pub manufacturer_id: Option<Uuid>,
    #[vortex(required, unique)]
    pub asset_code: String,
    #[vortex(required)]
    pub name: String,
    pub tag_number: Option<String>,
    pub description: Option<String>,
    /// Legacy manufacturer field (deprecated, use manufacturer_id)
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub year_manufactured: Option<i32>,
    /// Full manufacture date (supplements year_manufactured)
    pub manufacture_date: Option<String>,
    /// Date equipment was installed at site
    pub installation_date: Option<String>,
    pub commissioning_date: Option<String>,
    pub warranty_expiry: Option<String>,
    pub expected_life_years: Option<i32>,
    pub purchase_cost: Option<f64>,
    pub replacement_cost: Option<f64>,
    /// Rated voltage in kV (base equipment level)
    pub rated_voltage_kv: Option<f64>,
    /// Rated current in Amperes (base equipment level)
    pub rated_current_a: Option<f64>,
    /// Rated power in kVA (base equipment level)
    pub rated_power_kva: Option<f64>,
    pub criticality_rating: Option<i32>,
    pub operational_status: Option<String>,
    /// Condition assessment: good, fair, poor, critical, unknown
    pub condition_status: Option<String>,
    pub condition_score: Option<f64>,
    /// Computed health index (0-100 scale)
    pub health_index: Option<f64>,
    pub last_inspection_date: Option<String>,
    pub last_maintenance_date: Option<String>,
    pub next_maintenance_date: Option<String>,
    pub notes: Option<String>,
    pub qr_code: Option<String>,
    pub qr_code_generated_at: Option<DateTime<Utc>>,
    pub display_order: Option<i32>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Asset Attribute (Dynamic type-specific fields)
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_asset_attributes", module = "asset_management", multi_tenant = false)]
pub struct AssetAttribute {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    #[vortex(required)]
    pub attribute_name: String,
    pub attribute_label: Option<String>,
    pub attribute_group: Option<String>,
    pub value_text: Option<String>,
    pub value_numeric: Option<f64>,
    pub value_boolean: Option<bool>,
    pub value_date: Option<String>,
    pub unit: Option<String>,
    pub data_type: Option<String>,
    pub display_order: Option<i32>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Component (L5) - Sub-component of an Asset
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_components", module = "asset_management", multi_tenant = false)]
pub struct Component {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub asset_id: Uuid,
    pub parent_id: Option<Uuid>,
    #[vortex(required)]
    pub code: String,
    #[vortex(required)]
    pub name: String,
    pub component_type: Option<String>,
    pub description: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub year_manufactured: Option<i32>,
    pub installation_date: Option<String>,
    pub warranty_expiry: Option<String>,
    pub status: Option<String>,
    pub condition_score: Option<f64>,
    pub qr_code: Option<String>,
    pub qr_code_generated_at: Option<DateTime<Utc>>,
    pub display_order: Option<i32>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Part (L6-7) - Replaceable part within a Component
/// Supports self-referencing hierarchy for sub-parts
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_parts", module = "asset_management", multi_tenant = false)]
pub struct Part {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub component_id: Uuid,
    /// Self-referencing for sub-parts (L7)
    pub parent_part_id: Option<Uuid>,
    #[vortex(required)]
    pub code: String,
    #[vortex(required)]
    pub name: String,
    /// Part type: consumable, spare, critical_spare, wear_part
    pub part_type: Option<String>,
    pub description: Option<String>,
    pub manufacturer: Option<String>,
    pub part_number: Option<String>,
    pub serial_number: Option<String>,
    /// Quantity installed
    pub quantity: Option<i32>,
    /// Minimum stock level for reorder
    pub reorder_level: Option<i32>,
    /// Unit of measure
    pub uom: Option<String>,
    pub unit_cost: Option<f64>,
    pub installation_date: Option<String>,
    pub warranty_expiry: Option<String>,
    pub expected_life_hours: Option<i32>,
    pub status: Option<String>,
    pub condition_score: Option<f64>,
    pub qr_code: Option<String>,
    pub qr_code_generated_at: Option<DateTime<Utc>>,
    pub display_order: Option<i32>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}
