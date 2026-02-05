//! Auto-Sequence Generation Service
//!
//! Generates unique sequential codes for various EAM entities

use chrono::Utc;

use vortex_common::{VortexResult, VortexError};
use vortex_orm::ConnectionPool;

/// Sequence types for different entities
#[derive(Debug, Clone, Copy)]
pub enum SequenceType {
    /// Equipment/Asset codes: EQP/000001
    Equipment,
    /// Component codes: CMP/000001
    Component,
    /// Part codes: PRT/000001
    Part,
    /// Maintenance/Work Order codes: MNT/2026/00001 (includes year)
    Maintenance,
    /// Inspection codes: INS/2026/00001 (includes year)
    Inspection,
}

impl SequenceType {
    /// Returns the sequence key (used to identify sequence in table)
    fn key(&self) -> &'static str {
        match self {
            SequenceType::Equipment => "equipment",
            SequenceType::Component => "component",
            SequenceType::Part => "part",
            SequenceType::Maintenance => "maintenance",
            SequenceType::Inspection => "inspection",
        }
    }

    /// Returns the prefix for generated codes
    fn prefix(&self) -> &'static str {
        match self {
            SequenceType::Equipment => "EQP",
            SequenceType::Component => "CMP",
            SequenceType::Part => "PRT",
            SequenceType::Maintenance => "MNT",
            SequenceType::Inspection => "INS",
        }
    }

    /// Whether this sequence includes year in the format
    fn includes_year(&self) -> bool {
        matches!(self, SequenceType::Maintenance | SequenceType::Inspection)
    }

    /// Number of digits for the sequence number
    fn digits(&self) -> usize {
        match self {
            SequenceType::Equipment | SequenceType::Component | SequenceType::Part => 6,
            SequenceType::Maintenance | SequenceType::Inspection => 5,
        }
    }
}

/// Gets the next sequence number and formats the code
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `seq_type` - Type of sequence to generate
///
/// # Returns
/// Formatted code string (e.g., "EQP/000001", "MNT/2026/00001")
pub async fn next_code(pool: &ConnectionPool, seq_type: SequenceType) -> VortexResult<String> {
    let current_year = Utc::now().format("%Y").to_string();

    // For year-based sequences, include year in the key
    let key = if seq_type.includes_year() {
        format!("{}_{}", seq_type.key(), current_year)
    } else {
        seq_type.key().to_string()
    };

    // Use UPSERT to atomically get next value
    // This ensures no duplicates even under concurrent access
    let next_val: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO eam_sequences (sequence_key, current_value)
        VALUES ($1, 1)
        ON CONFLICT (sequence_key) DO UPDATE
        SET current_value = eam_sequences.current_value + 1
        RETURNING current_value
        "#
    )
        .bind(&key)
        .fetch_one(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    // Format the code
    let formatted = if seq_type.includes_year() {
        format!(
            "{}/{}/{:0width$}",
            seq_type.prefix(),
            current_year,
            next_val,
            width = seq_type.digits()
        )
    } else {
        format!(
            "{}/{:0width$}",
            seq_type.prefix(),
            next_val,
            width = seq_type.digits()
        )
    };

    Ok(formatted)
}

/// Generates next equipment code: EQP/000001
pub async fn next_equipment_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::Equipment).await
}

/// Generates next component code: CMP/000001
pub async fn next_component_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::Component).await
}

/// Generates next part code: PRT/000001
pub async fn next_part_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::Part).await
}

/// Generates next maintenance/work order code: MNT/2026/00001
pub async fn next_maintenance_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::Maintenance).await
}

/// Generates next inspection code: INS/2026/00001
pub async fn next_inspection_code(pool: &ConnectionPool) -> VortexResult<String> {
    next_code(pool, SequenceType::Inspection).await
}

/// Peeks at the next sequence value without incrementing
///
/// Useful for displaying "next code will be..." without reserving it
pub async fn peek_next_code(pool: &ConnectionPool, seq_type: SequenceType) -> VortexResult<String> {
    let current_year = Utc::now().format("%Y").to_string();

    let key = if seq_type.includes_year() {
        format!("{}_{}", seq_type.key(), current_year)
    } else {
        seq_type.key().to_string()
    };

    // Get current value (or 0 if not exists)
    let current_val: Option<i64> = sqlx::query_scalar(
        "SELECT current_value FROM eam_sequences WHERE sequence_key = $1"
    )
        .bind(&key)
        .fetch_optional(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let next_val = current_val.unwrap_or(0) + 1;

    let formatted = if seq_type.includes_year() {
        format!(
            "{}/{}/{:0width$}",
            seq_type.prefix(),
            current_year,
            next_val,
            width = seq_type.digits()
        )
    } else {
        format!(
            "{}/{:0width$}",
            seq_type.prefix(),
            next_val,
            width = seq_type.digits()
        )
    };

    Ok(formatted)
}

/// Resets a sequence to a specific value
///
/// WARNING: Use with caution - can cause duplicate codes if misused
pub async fn reset_sequence(
    pool: &ConnectionPool,
    seq_type: SequenceType,
    value: i64,
) -> VortexResult<()> {
    let current_year = Utc::now().format("%Y").to_string();

    let key = if seq_type.includes_year() {
        format!("{}_{}", seq_type.key(), current_year)
    } else {
        seq_type.key().to_string()
    };

    sqlx::query(
        r#"
        INSERT INTO eam_sequences (sequence_key, current_value)
        VALUES ($1, $2)
        ON CONFLICT (sequence_key) DO UPDATE
        SET current_value = $2
        "#
    )
        .bind(&key)
        .bind(value)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(())
}

/// SQL to create the sequences table (should be in migration)
pub const CREATE_SEQUENCES_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS eam_sequences (
    sequence_key VARCHAR(100) PRIMARY KEY,
    current_value BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_eam_sequences_key ON eam_sequences(sequence_key);

COMMENT ON TABLE eam_sequences IS 'Auto-increment sequences for EAM codes';
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_type_properties() {
        assert_eq!(SequenceType::Equipment.prefix(), "EQP");
        assert_eq!(SequenceType::Equipment.digits(), 6);
        assert!(!SequenceType::Equipment.includes_year());

        assert_eq!(SequenceType::Maintenance.prefix(), "MNT");
        assert_eq!(SequenceType::Maintenance.digits(), 5);
        assert!(SequenceType::Maintenance.includes_year());
    }

    #[test]
    fn test_format_equipment_code() {
        // Manual formatting test (without DB)
        let seq_type = SequenceType::Equipment;
        let next_val = 42_i64;
        let formatted = format!(
            "{}/{:0width$}",
            seq_type.prefix(),
            next_val,
            width = seq_type.digits()
        );
        assert_eq!(formatted, "EQP/000042");
    }

    #[test]
    fn test_format_maintenance_code() {
        let seq_type = SequenceType::Maintenance;
        let next_val = 123_i64;
        let year = "2026";
        let formatted = format!(
            "{}/{}/{:0width$}",
            seq_type.prefix(),
            year,
            next_val,
            width = seq_type.digits()
        );
        assert_eq!(formatted, "MNT/2026/00123");
    }
}
