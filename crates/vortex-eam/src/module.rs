//! EAM Module Implementation
//!
//! Implements the Vortex Module trait for lifecycle management.
//! SESB Specification Parity - 8-level hierarchy with expanded equipment types.

use std::sync::OnceLock;
use async_trait::async_trait;
use tracing::{info, warn};

use vortex_common::{ModuleId, VortexResult};
use vortex_module::{
    ModuleManifest, ModuleState, HookRegistry,
    manifest::{ModuleCategory, ModuleDependency},
    loader::Module,
};

/// EAM Module - Enterprise Asset Management
/// SESB Specification Parity Implementation
pub struct EamModule;

impl EamModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EamModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Module for EamModule {
    fn manifest(&self) -> &ModuleManifest {
        static MANIFEST: OnceLock<ModuleManifest> = OnceLock::new();
        MANIFEST.get_or_init(|| {
            ModuleManifest {
                id: ModuleId::new("asset_management"),
                name: "Enterprise Asset Management".to_string(),
                version: "0.2.0".to_string(),
                description: Some(
                    "Distribution Substation Asset Management module with SESB specification parity. \
                    8-level hierarchy (Region → Site → Substation → Bay → Asset → Component → Part), \
                    expanded equipment types, specialized condition monitoring, and workflow state machine.".to_string()
                ),
                author: Some("Vortex Team".to_string()),
                license: None,
                website: None,
                category: ModuleCategory::Utility,
                dependencies: vec![
                    ModuleDependency {
                        module_id: ModuleId::new("base"),
                        version_constraint: ">=0.1.0".to_string(),
                        optional: false,
                    },
                ],
                conflicts: vec![],
                is_core: false,
                removable: true,
                auto_install: false,
                state: ModuleState::Uninstalled,
                installed_at: None,
                updated_at: None,
                models: vec![
                    // Configuration models
                    "Manufacturer".to_string(),
                    "VoltageLevel".to_string(),
                    "UnitType".to_string(),
                    "AssetCategory".to_string(),
                    "AssetStatus".to_string(),
                    // Hierarchy models (8-level)
                    "Region".to_string(),
                    "Site".to_string(),
                    "Substation".to_string(),
                    "Bay".to_string(),
                    "FunctionalLocation".to_string(), // Legacy
                    "Asset".to_string(),
                    "AssetAttribute".to_string(),
                    "Component".to_string(),
                    "Part".to_string(),
                    // Equipment-specific models (original)
                    "Transformer".to_string(),
                    "SwitchGear".to_string(),
                    "RingMainUnit".to_string(),
                    "FeederPillar".to_string(),
                    "ProtectionSystem".to_string(),
                    "ScadaSystem".to_string(),
                    "Battery".to_string(),
                    // Equipment-specific models (new per SESB)
                    "CurrentVoltageTransformer".to_string(),
                    "SurgeArrester".to_string(),
                    "Cable".to_string(),
                    "Busbar".to_string(),
                    "Isolator".to_string(),
                    "EarthingSystem".to_string(),
                    // Maintenance models
                    "MaintenanceSchedule".to_string(),
                    "WorkOrder".to_string(),
                    "WorkOrderStateHistory".to_string(),
                    "InspectionResult".to_string(),
                    "MaintenancePlan".to_string(),
                    "MaintenancePartLine".to_string(),
                    // Checklist models
                    "ChecklistTemplate".to_string(),
                    "ChecklistTemplateItem".to_string(),
                    "ChecklistLine".to_string(),
                    // Condition monitoring (generic)
                    "ConditionMonitoringRecord".to_string(),
                    "AssetHealthIndex".to_string(),
                    // Condition monitoring (specialized)
                    "DgaAnalysis".to_string(),
                    "OilQualityTest".to_string(),
                    "ThermalImaging".to_string(),
                    "PartialDischarge".to_string(),
                    "InsulationResistance".to_string(),
                    "Sf6Analysis".to_string(),
                    "ContactTimingTest".to_string(),
                    "BatteryDischargeTest".to_string(),
                ],
                migrations: vec![
                    "100_eam_base".to_string(),
                    "101_eam_hierarchy_expansion".to_string(),
                    "102_eam_master_data".to_string(),
                    "103_eam_equipment_types".to_string(),
                    "104_eam_condition_monitoring".to_string(),
                    "105_eam_maintenance_workflows".to_string(),
                    "106_eam_checklist_plans".to_string(),
                ],
            }
        })
    }

    async fn install(&self) -> VortexResult<()> {
        info!("Installing EAM module...");
        info!("EAM module installed successfully");
        Ok(())
    }

    async fn upgrade(&self, from_version: &str) -> VortexResult<()> {
        info!("Upgrading EAM module from version {}", from_version);
        info!("EAM module upgraded successfully");
        Ok(())
    }

    async fn uninstall(&self) -> VortexResult<()> {
        warn!("Uninstalling EAM module - all asset data will be removed!");
        info!("EAM module uninstalled");
        Ok(())
    }

    async fn load(&self) -> VortexResult<()> {
        info!("Loading EAM module...");
        info!("EAM module loaded and active");
        Ok(())
    }

    async fn unload(&self) -> VortexResult<()> {
        info!("Unloading EAM module...");
        Ok(())
    }

    fn register_models(&self) {
        info!("Registering EAM models...");
        info!("EAM models registered: {} models", self.manifest().models.len());
    }

    fn register_hooks(&self, _registry: &HookRegistry) {
        info!("EAM hooks registered");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest() {
        let module = EamModule::new();
        let manifest = module.manifest();

        assert_eq!(manifest.id.0, "asset_management");
        assert_eq!(manifest.name, "Enterprise Asset Management");
        assert!(!manifest.is_core);
        assert!(manifest.removable);
    }
}
