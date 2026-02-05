//! Checklist System Models
//!
//! Checklist templates with configurable input types, scoring, and instantiation
//! as checklist lines on work orders. Ported from SESB EAM Odoo module.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_macros::Model;

/// Checklist Template
///
/// Defines a reusable checklist for a specific equipment category and maintenance type.
/// Templates contain items that get copied to ChecklistLine records when a work order
/// generates its checklist.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_checklist_templates", module = "asset_management")]
pub struct ChecklistTemplate {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub company_id: Uuid,
    #[vortex(required)]
    pub name: String,
    /// Equipment category: transformer, switchgear, rmu, protection, scada, battery, etc.
    #[vortex(required)]
    pub equipment_category: String,
    /// Maintenance type: pm, cm, emergency, inspection, testing, overhaul
    #[vortex(required)]
    pub maintenance_type: String,
    pub version: Option<i32>,
    pub description: Option<String>,
    pub is_active: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}

/// Checklist Template Item
///
/// Individual check item within a template. Supports 6 input types:
/// - pass_fail: Pass / Fail / N/A
/// - yes_no: Yes / No
/// - measurement: Numeric value with unit and min/max thresholds
/// - text: Free text observation
/// - selection: Dropdown from predefined options (stored as JSON)
/// - rating: Numeric rating scale (1 to rating_scale_max)
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_checklist_template_items", module = "asset_management", multi_tenant = false)]
pub struct ChecklistTemplateItem {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub template_id: Uuid,
    #[vortex(required)]
    pub name: String,
    pub description: Option<String>,
    pub sequence: Option<i32>,
    pub section: Option<String>,
    /// Input type: pass_fail, yes_no, measurement, text, selection, rating
    #[vortex(required)]
    pub input_type: String,
    // Measurement configuration
    pub measurement_unit: Option<String>,
    pub measurement_min: Option<f64>,
    pub measurement_max: Option<f64>,
    // Selection configuration (JSON array of {value, label, score_value, is_fail})
    pub selection_options: Option<serde_json::Value>,
    // Rating configuration
    pub rating_scale_max: Option<i32>,
    // Flags
    pub is_required: Option<bool>,
    /// If critical item fails, entire checklist fails
    pub is_critical: Option<bool>,
    pub is_scored: Option<bool>,
    pub weight: Option<f64>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Checklist Line
///
/// An instantiated checklist item on a work order. Created by copying from
/// ChecklistTemplateItem. Contains both the configuration (copied) and
/// the user-entered values.
///
/// Scoring logic:
/// - pass_fail: pass=100, fail=0, na=100
/// - yes_no: yes=100, no=0
/// - measurement: 100 if in range, 0 if out of range (with deviation scoring)
/// - text: 100 if filled, 0 if empty
/// - selection: score_value from selected option
/// - rating: (value / max) * 100
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "eam_checklist_lines", module = "asset_management", multi_tenant = false)]
pub struct ChecklistLine {
    #[vortex(primary_key)]
    pub id: Uuid,
    #[vortex(required, indexed)]
    pub work_order_id: Uuid,
    /// Reference back to template item (nullable, for traceability)
    pub template_item_id: Option<Uuid>,
    // Copied from template item
    #[vortex(required)]
    pub name: String,
    pub description: Option<String>,
    pub sequence: Option<i32>,
    pub section: Option<String>,
    #[vortex(required)]
    pub input_type: String,
    // Measurement config (copied)
    pub measurement_unit: Option<String>,
    pub measurement_min: Option<f64>,
    pub measurement_max: Option<f64>,
    // Selection config (copied, JSON)
    pub selection_options: Option<serde_json::Value>,
    // Rating config (copied)
    pub rating_scale_max: Option<i32>,
    // Flags (copied)
    pub is_required: Option<bool>,
    pub is_critical: Option<bool>,
    pub is_scored: Option<bool>,
    pub weight: Option<f64>,
    // === User-input value fields (one per input type) ===
    /// Result for pass_fail type: pass, fail, na
    pub value_pass_fail: Option<String>,
    /// Answer for yes_no type: yes, no
    pub value_yes_no: Option<String>,
    /// Numeric value for measurement type
    pub value_measurement: Option<f64>,
    /// Text observation for text type
    pub value_text: Option<String>,
    /// Selected value key for selection type
    pub value_selection: Option<String>,
    /// Rating value for rating type
    pub value_rating: Option<i32>,
    // === Computed status fields ===
    /// Whether this line has been completed (value entered)
    pub is_completed: Option<bool>,
    /// Computed score (0-100)
    pub line_score: Option<f64>,
    /// Whether measurement is outside min/max thresholds
    pub is_out_of_range: Option<bool>,
    /// Whether this item is in a failed state
    pub is_failed: Option<bool>,
    /// Tracks explicit measurement write (handles 0.0 as valid)
    pub measurement_filled: Option<bool>,
    /// User remarks/notes
    pub note: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}
