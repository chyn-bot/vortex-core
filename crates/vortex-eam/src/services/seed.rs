//! Seed Data Service
//!
//! Creates default configuration data for EAM module

use tracing::info;
use uuid::Uuid;

use vortex_common::{VortexResult, VortexError, CompanyId};
use vortex_orm::ConnectionPool;

/// Seeds default EAM configuration data for a company
pub async fn seed_eam_defaults(pool: &ConnectionPool, company_id: &CompanyId) -> VortexResult<()> {
    info!("Seeding EAM defaults for company {:?}", company_id);

    // Seed voltage levels (AC and DC)
    seed_voltage_levels(pool, company_id).await?;

    // Seed unit types
    seed_unit_types(pool, company_id).await?;

    // Seed asset categories
    seed_asset_categories(pool, company_id).await?;

    // Seed asset statuses
    seed_asset_statuses(pool, company_id).await?;

    // Seed manufacturers
    seed_manufacturers(pool, company_id).await?;

    info!("EAM seed data created successfully");
    Ok(())
}

async fn seed_voltage_levels(pool: &ConnectionPool, company_id: &CompanyId) -> VortexResult<()> {
    // AC voltage levels (code, name, value, class, type)
    let ac_levels = vec![
        ("275KV", "275 kV", 275.0, "EHV", "ac"),
        ("132KV", "132 kV", 132.0, "HV", "ac"),
        ("33KV", "33 kV", 33.0, "HV", "ac"),
        ("22KV", "22 kV", 22.0, "MV", "ac"),
        ("11KV", "11 kV", 11.0, "MV", "ac"),
        ("6.6KV", "6.6 kV", 6.6, "MV", "ac"),
        ("0.415KV", "0.415 kV (415V)", 0.415, "LV", "ac"),
        ("0.240KV", "0.240 kV (240V)", 0.240, "LV", "ac"),
    ];

    // DC voltage levels for control systems and batteries
    let dc_levels = vec![
        ("110VDC", "110 V DC", 0.110, "DC", "dc"),
        ("48VDC", "48 V DC", 0.048, "DC", "dc"),
        ("24VDC", "24 V DC", 0.024, "DC", "dc"),
        ("12VDC", "12 V DC", 0.012, "DC", "dc"),
    ];

    let all_levels: Vec<_> = ac_levels.into_iter().chain(dc_levels.into_iter()).collect();

    for (i, (code, name, value, class, vtype)) in all_levels.iter().enumerate() {
        let sql = r#"
            INSERT INTO eam_voltage_levels (id, company_id, code, name, voltage_value, voltage_unit, voltage_class, voltage_type, display_order, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, 'kV', $6, $7, $8, true, NOW(), NOW())
            ON CONFLICT (company_id, code) DO NOTHING
        "#;
        sqlx::query(sql)
            .bind(Uuid::new_v4())
            .bind(&company_id.0)
            .bind(code)
            .bind(name)
            .bind(value)
            .bind(class)
            .bind(vtype)
            .bind(i as i32)
            .execute(pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }

    Ok(())
}

async fn seed_unit_types(pool: &ConnectionPool, company_id: &CompanyId) -> VortexResult<()> {
    let unit_types = vec![
        ("PPU", "Primary Plant Unit", "PPU"),
        ("SSU33", "Switching Station Unit 33kV", "SSU 33kV"),
        ("SSU11", "Switching Station Unit 11kV", "SSU 11kV"),
        ("PP", "Primary Plant", "PP"),
        ("PE", "Primary Equipment", "PE"),
        ("SEC", "Secondary Equipment", "Secondary"),
    ];

    for (i, (code, name, short_name)) in unit_types.iter().enumerate() {
        let sql = r#"
            INSERT INTO eam_unit_types (id, company_id, code, name, short_name, display_order, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, true, NOW(), NOW())
            ON CONFLICT (company_id, code) DO NOTHING
        "#;
        sqlx::query(sql)
            .bind(Uuid::new_v4())
            .bind(&company_id.0)
            .bind(code)
            .bind(name)
            .bind(short_name)
            .bind(i as i32)
            .execute(pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }

    Ok(())
}

async fn seed_asset_categories(pool: &ConnectionPool, company_id: &CompanyId) -> VortexResult<()> {
    let categories = vec![
        ("TX", "Transformer", "#FF6B6B", 365),
        ("SG", "Switch Gear", "#4ECDC4", 365),
        ("FP", "Feeder Pillar", "#45B7D1", 180),
        ("RMU", "Ring Main Unit", "#96CEB4", 365),
        ("PROT", "Protection System", "#FFEAA7", 365),
        ("SCADA", "SCADA System", "#DDA0DD", 365),
        ("BAT", "Battery", "#98D8C8", 180),
        ("CT", "Current Transformer", "#F7DC6F", 365),
        ("VT", "Voltage Transformer", "#BB8FCE", 365),
        ("ISO", "Isolator", "#85C1E9", 365),
        ("SA", "Surge Arrester", "#F8B500", 365),
        ("CABLE", "Cable", "#A569BD", 730),
    ];

    for (i, (code, name, color, pm_interval)) in categories.iter().enumerate() {
        let sql = r#"
            INSERT INTO eam_asset_categories (id, company_id, code, name, color, display_order, default_pm_interval_days, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, true, NOW(), NOW())
            ON CONFLICT (company_id, code) DO NOTHING
        "#;
        sqlx::query(sql)
            .bind(Uuid::new_v4())
            .bind(&company_id.0)
            .bind(code)
            .bind(name)
            .bind(color)
            .bind(i as i32)
            .bind(pm_interval)
            .execute(pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }

    Ok(())
}

async fn seed_asset_statuses(pool: &ConnectionPool, company_id: &CompanyId) -> VortexResult<()> {
    let statuses = vec![
        ("ACTIVE", "In Service", "#28A745", true, true, false),
        ("MAINT", "Under Maintenance", "#FFC107", false, true, false),
        ("STANDBY", "Standby", "#17A2B8", true, true, false),
        ("FAULTY", "Faulty", "#DC3545", false, true, false),
        ("COMMISSIONING", "Commissioning", "#6F42C1", false, false, false),
        ("DECOM", "Decommissioned", "#6C757D", false, false, true),
    ];

    for (i, (code, name, color, is_op, allows_maint, is_final)) in statuses.iter().enumerate() {
        let sql = r#"
            INSERT INTO eam_asset_statuses (id, company_id, code, name, color, is_operational, allows_maintenance, is_final, display_order, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, NOW(), NOW())
            ON CONFLICT (company_id, code) DO NOTHING
        "#;
        sqlx::query(sql)
            .bind(Uuid::new_v4())
            .bind(&company_id.0)
            .bind(code)
            .bind(name)
            .bind(color)
            .bind(is_op)
            .bind(allows_maint)
            .bind(is_final)
            .bind(i as i32)
            .execute(pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }

    Ok(())
}

/// Seeds common equipment manufacturers
async fn seed_manufacturers(pool: &ConnectionPool, company_id: &CompanyId) -> VortexResult<()> {
    // (code, name, country_code, country_name, is_approved)
    let manufacturers = vec![
        ("ABB", "ABB Ltd", "CH", "Switzerland", true),
        ("SIEMENS", "Siemens AG", "DE", "Germany", true),
        ("SCHNEIDER", "Schneider Electric", "FR", "France", true),
        ("GE", "General Electric", "US", "United States", true),
        ("HITACHI", "Hitachi Energy", "JP", "Japan", true),
        ("TOSHIBA", "Toshiba Corporation", "JP", "Japan", true),
        ("MITSUBISHI", "Mitsubishi Electric", "JP", "Japan", true),
        ("HYUNDAI", "Hyundai Electric", "KR", "South Korea", true),
        ("AREVA", "Areva T&D", "FR", "France", true),
        ("ALSTOM", "Alstom Grid", "FR", "France", true),
        ("EATON", "Eaton Corporation", "IE", "Ireland", true),
        ("LUCY", "Lucy Electric", "GB", "United Kingdom", true),
        ("ORMAZABAL", "Ormazabal", "ES", "Spain", true),
        ("CG", "CG Power and Industrial", "IN", "India", true),
        ("TBEA", "TBEA Co Ltd", "CN", "China", true),
        ("HYOSUNG", "Hyosung Heavy Industries", "KR", "South Korea", true),
        ("SEL", "Schweitzer Engineering Laboratories", "US", "United States", true),
        ("OMICRON", "OMICRON Electronics", "AT", "Austria", true),
        ("MEGGER", "Megger Group", "GB", "United Kingdom", true),
        ("EXIDE", "Exide Technologies", "US", "United States", true),
        ("SAFT", "Saft Groupe SA", "FR", "France", true),
        ("ENERSYS", "EnerSys", "US", "United States", true),
    ];

    for (i, (code, name, country_code, country_name, is_approved)) in manufacturers.iter().enumerate() {
        let sql = r#"
            INSERT INTO eam_manufacturers (id, company_id, code, name, country_code, country_name, is_approved_vendor, display_order, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, NOW(), NOW())
            ON CONFLICT (company_id, code) DO NOTHING
        "#;
        sqlx::query(sql)
            .bind(Uuid::new_v4())
            .bind(&company_id.0)
            .bind(code)
            .bind(name)
            .bind(country_code)
            .bind(country_name)
            .bind(is_approved)
            .bind(i as i32)
            .execute(pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    }

    Ok(())
}
