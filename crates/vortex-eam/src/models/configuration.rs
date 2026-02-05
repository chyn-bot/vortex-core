//! Configuration Models
//!
//! User-configurable settings: Voltage Levels, Unit Types, Asset Categories, Asset Statuses, Manufacturers

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_macros::Model;

/// Manufacturer - Equipment manufacturer master data
/// Centralizes manufacturer information for better tracking and reporting
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_manufacturers", module = "asset_management")]
pub struct Manufacturer {
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
    /// Country of origin (ISO 3166-1 alpha-2)
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub website: Option<String>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub address: Option<String>,
    /// Support contact information
    pub support_phone: Option<String>,
    pub support_email: Option<String>,
    /// Active warranty provider
    pub is_warranty_provider: Option<bool>,
    /// Approved vendor status
    pub is_approved_vendor: Option<bool>,
    pub approval_date: Option<String>,
    pub approval_expiry: Option<String>,
    pub display_order: Option<i32>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Voltage Level - User configurable
/// Examples: 275kV, 132kV, 33kV, 11kV, 0.415kV
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_voltage_levels", module = "asset_management")]
pub struct VoltageLevel {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required, indexed)]
    pub code: String,
    #[vortex(required)]
    pub name: String,
    #[vortex(required)]
    pub voltage_value: f64,
    pub voltage_unit: Option<String>,
    pub voltage_class: Option<String>,
    /// Voltage type: ac or dc
    pub voltage_type: Option<String>,
    pub description: Option<String>,
    pub display_order: Option<i32>,
    pub is_active: Option<bool>,
    pub is_deleted: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Unit Type - User configurable
/// Examples: PPU, SSU 33kV, SSU 11kV, PP, PE
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_unit_types", module = "asset_management")]
pub struct UnitType {
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
    pub display_order: Option<i32>,
    pub equipment_template: Option<serde_json::Value>,
    pub is_active: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Asset Category
/// Examples: Transformer, Switch Gear, Feeder Pillar, RMU, Protection, SCADA, Battery
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_asset_categories", module = "asset_management")]
pub struct AssetCategory {
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
    pub icon: Option<String>,
    pub color: Option<String>,
    pub parent_id: Option<Uuid>,
    pub display_order: Option<i32>,
    pub default_pm_interval_days: Option<i32>,
    pub attribute_template: Option<serde_json::Value>,
    pub is_active: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Asset Status
/// Examples: In Service, Under Maintenance, Faulty, Decommissioned
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_asset_statuses", module = "asset_management")]
pub struct AssetStatus {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required, indexed)]
    pub code: String,
    #[vortex(required)]
    pub name: String,
    pub description: Option<String>,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub is_operational: Option<bool>,
    pub allows_maintenance: Option<bool>,
    pub is_final: Option<bool>,
    pub display_order: Option<i32>,
    pub is_active: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}
