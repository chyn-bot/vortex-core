//! Maintenance models declared with `#[derive(Model)]`.
//!
//! Registry source of truth for the maintenance tables; reproduces migration
//! `002_maintenance_registry`. See `vortex_orm::registry_sync`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_orm::prelude::Model;

/// Registry projection of `maint_asset`.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "maint_asset", module = "maintenance", name = "maint_asset", label = "Assets")]
pub struct MaintAsset {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Code", ui_type = "string")]
    pub code: String,

    #[vortex(label = "Name", ui_type = "string")]
    pub name: String,

    #[vortex(label = "Category", references = "maint_asset_category")]
    pub category_id: Option<Uuid>,

    #[vortex(label = "Criticality", selection = "low,medium,high,critical")]
    pub criticality: String,

    #[vortex(label = "State", selection = "operational,under_maintenance,down,decommissioned")]
    pub state: String,
}

/// Registry projection of `maint_work_order`.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "maint_work_order", module = "maintenance", name = "maint_work_order", label = "Work Orders")]
pub struct MaintWorkOrder {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Number", ui_type = "string")]
    pub number: String,

    #[vortex(label = "Asset", references = "maint_asset")]
    pub asset_id: Option<Uuid>,

    #[vortex(label = "Type", selection = "corrective,preventive,inspection")]
    pub wo_type: String,

    #[vortex(label = "Priority", selection = "low,normal,high,urgent")]
    pub priority: String,

    #[vortex(label = "Status", selection = "draft,in_progress,done,cancelled")]
    pub state: String,
}

/// Registry projection of `maint_plan`.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "maint_plan", module = "maintenance", name = "maint_plan", label = "Maintenance Plans")]
pub struct MaintPlan {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Name", ui_type = "string")]
    pub name: String,

    #[vortex(label = "Asset", references = "maint_asset")]
    pub asset_id: Option<Uuid>,

    #[vortex(label = "Frequency", selection = "day,week,month,year")]
    pub frequency_unit: String,

    #[vortex(label = "Next Date", ui_type = "date")]
    pub next_date: String,

    #[vortex(label = "State", selection = "active,paused")]
    pub state: String,
}
