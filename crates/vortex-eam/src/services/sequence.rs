//! EAM sequence catalog — thin wrapper over the core sequence service.
//!
//! The real implementation lives in [`vortex_orm::sequence`] since
//! sequence generation is a platform primitive every vertical needs.
//! This module keeps the historical `SequenceType` enum and the typed
//! `next_*_code` helpers so existing EAM call sites do not change —
//! but all of them simply hand a [`SequenceSpec`] to the core service.
//!
//! When adding a new EAM sequence:
//!
//! 1. Add a variant to [`SequenceType`].
//! 2. Map it to a `const` [`SequenceSpec`] in [`SequenceType::spec`].
//!    Use the dotted namespace `eam.<thing>` so it can't collide with
//!    sequences from other plugins.
//! 3. Optionally add a typed `next_<thing>_code` wrapper for
//!    ergonomics.
//!
//! All of this is plain const data — no DB migration needed when
//! adding a new sequence type, because the `sequences` table is
//! key-value and rows are lazily created on first `next()` call.

use vortex_common::VortexResult;
use vortex_orm::sequence::{self, SequenceSpec};
use vortex_orm::ConnectionPool;

/// Sequence types used by the EAM plugin. Each variant resolves to a
/// [`SequenceSpec`] via [`SequenceType::spec`] and is fulfilled by the
/// core [`vortex_orm::sequence`] service.
#[derive(Debug, Clone, Copy)]
pub enum SequenceType {
    /// Equipment / asset codes: `EQP/000001`
    Equipment,
    /// Component codes: `CMP/000001`
    Component,
    /// Part codes: `PRT/000001`
    Part,
    /// Maintenance / work-order codes: `MNT/2026/00001` (resets yearly)
    Maintenance,
    /// Inspection codes: `INS/2026/00001` (resets yearly)
    Inspection,
    /// Maintenance plan codes: `MP/00001`
    MaintenancePlan,
    /// Transmission line codes: `TL/00001`
    TransmissionLine,
    /// Transmission tower codes: `TWR/000001`
    TransmissionTower,
    /// Condition monitoring codes: `CM/2026/00001` (resets yearly)
    ConditionMonitoring,
}

impl SequenceType {
    /// Resolve this sequence type to its core [`SequenceSpec`].
    ///
    /// All specs are `const` so they compose into a compile-time
    /// catalog with no allocations and no runtime dispatch beyond the
    /// `match`.
    pub const fn spec(self) -> SequenceSpec {
        match self {
            SequenceType::Equipment => {
                SequenceSpec::new("eam.equipment", "EQP").with_padding(6)
            }
            SequenceType::Component => {
                SequenceSpec::new("eam.component", "CMP").with_padding(6)
            }
            SequenceType::Part => {
                SequenceSpec::new("eam.part", "PRT").with_padding(6)
            }
            SequenceType::Maintenance => {
                SequenceSpec::new("eam.maintenance", "MNT")
                    .with_padding(5)
                    .yearly()
            }
            SequenceType::Inspection => {
                SequenceSpec::new("eam.inspection", "INS")
                    .with_padding(5)
                    .yearly()
            }
            SequenceType::MaintenancePlan => {
                SequenceSpec::new("eam.maintenance_plan", "MP").with_padding(5)
            }
            SequenceType::TransmissionLine => {
                SequenceSpec::new("eam.transmission_line", "TL").with_padding(5)
            }
            SequenceType::TransmissionTower => {
                SequenceSpec::new("eam.transmission_tower", "TWR").with_padding(6)
            }
            SequenceType::ConditionMonitoring => {
                SequenceSpec::new("eam.condition_monitoring", "CM")
                    .with_padding(5)
                    .yearly()
            }
        }
    }
}

/// Consume the next code for a given EAM sequence type.
pub async fn next_code(pool: &ConnectionPool, seq_type: SequenceType) -> VortexResult<String> {
    sequence::next(pool, &seq_type.spec()).await
}

/// Peek at the next code without consuming it. Only valid for preview
/// UI — the returned code is not reserved and may be handed to another
/// caller by the next [`next_code`] invocation.
pub async fn peek_next_code(
    pool: &ConnectionPool,
    seq_type: SequenceType,
) -> VortexResult<String> {
    sequence::peek(pool, &seq_type.spec()).await
}

/// Administrative reset of a sequence's current-period counter. See
/// [`vortex_orm::sequence::reset`] for the warnings.
pub async fn reset_sequence(
    pool: &ConnectionPool,
    seq_type: SequenceType,
    value: i64,
) -> VortexResult<()> {
    sequence::reset(pool, &seq_type.spec(), value).await
}

// ---------------------------------------------------------------------------
// Typed ergonomic wrappers for each EAM sequence type. These are the
// functions existing handlers import — keeping them unchanged means the
// promotion from plugin-local to core service is transparent to callers.
// ---------------------------------------------------------------------------

/// Generates the next equipment code: `EQP/000001`.
pub async fn next_equipment_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::Equipment).await
}

/// Generates the next component code: `CMP/000001`.
pub async fn next_component_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::Component).await
}

/// Generates the next part code: `PRT/000001`.
pub async fn next_part_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::Part).await
}

/// Generates the next maintenance / work-order code: `MNT/2026/00001`.
pub async fn next_maintenance_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::Maintenance).await
}

/// Generates the next inspection code: `INS/2026/00001`.
pub async fn next_inspection_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::Inspection).await
}

/// Generates the next maintenance plan code: `MP/00001`.
pub async fn next_maintenance_plan_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::MaintenancePlan).await
}

/// Generates the next transmission line code: `TL/00001`.
pub async fn next_transmission_line_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::TransmissionLine).await
}

/// Generates the next transmission tower code: `TWR/000001`.
pub async fn next_transmission_tower_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::TransmissionTower).await
}

/// Generates the next condition monitoring code: `CM/2026/00001`.
pub async fn next_condition_monitoring_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::ConditionMonitoring).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equipment_spec_matches_legacy_format() {
        let spec = SequenceType::Equipment.spec();
        assert_eq!(spec.code, "eam.equipment");
        assert_eq!(spec.prefix, "EQP");
        assert_eq!(spec.padding, 6);
    }

    #[test]
    fn maintenance_spec_is_yearly() {
        let spec = SequenceType::Maintenance.spec();
        assert_eq!(spec.code, "eam.maintenance");
        assert_eq!(spec.prefix, "MNT");
        assert_eq!(spec.padding, 5);
        assert!(matches!(
            spec.scope,
            vortex_orm::sequence::SequenceScope::Yearly
        ));
    }

    #[test]
    fn condition_monitoring_spec_is_yearly() {
        let spec = SequenceType::ConditionMonitoring.spec();
        assert_eq!(spec.code, "eam.condition_monitoring");
        assert_eq!(spec.prefix, "CM");
        assert!(matches!(
            spec.scope,
            vortex_orm::sequence::SequenceScope::Yearly
        ));
    }
}
