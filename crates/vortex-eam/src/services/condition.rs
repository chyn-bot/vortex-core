//! Condition Monitoring Services
//!
//! DGA fault classification, status assessment, and related analysis functions

use crate::models::DgaAnalysis;

/// DGA Fault Types from Duval Triangle analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DgaFaultType {
    /// No significant fault (normal aging)
    Normal,
    /// Partial Discharge (PD)
    PartialDischarge,
    /// Low Energy Discharge (D1) - sparking
    LowEnergyDischarge,
    /// High Energy Discharge (D2) - arcing
    HighEnergyDischarge,
    /// Thermal Fault < 300°C (T1)
    ThermalFaultLow,
    /// Thermal Fault 300-700°C (T2)
    ThermalFaultMedium,
    /// Thermal Fault > 700°C (T3)
    ThermalFaultHigh,
    /// Mixed thermal and electrical (DT)
    MixedFault,
    /// Stray gassing / oil overheating
    StrayGassing,
}

impl DgaFaultType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DgaFaultType::Normal => "normal",
            DgaFaultType::PartialDischarge => "partial_discharge",
            DgaFaultType::LowEnergyDischarge => "low_energy_discharge",
            DgaFaultType::HighEnergyDischarge => "high_energy_discharge",
            DgaFaultType::ThermalFaultLow => "thermal_fault_t1",
            DgaFaultType::ThermalFaultMedium => "thermal_fault_t2",
            DgaFaultType::ThermalFaultHigh => "thermal_fault_t3",
            DgaFaultType::MixedFault => "mixed_fault_dt",
            DgaFaultType::StrayGassing => "stray_gassing",
        }
    }
}

/// DGA Status levels per IEEE C57.104
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DgaStatus {
    /// Condition 1 - Normal
    Normal,
    /// Condition 2 - Caution, increased monitoring
    Caution,
    /// Condition 3 - Warning, plan intervention
    Warning,
    /// Condition 4 - Critical, immediate action
    Critical,
}

impl DgaStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DgaStatus::Normal => "normal",
            DgaStatus::Caution => "caution",
            DgaStatus::Warning => "warning",
            DgaStatus::Critical => "critical",
        }
    }
}

/// Classifies DGA fault type using the Duval Triangle method
///
/// The Duval Triangle uses ratios of CH4, C2H4, and C2H2 to determine fault type.
/// Reference: IEC 60599, Duval Triangle Method
pub fn classify_dga_fault(dga: &DgaAnalysis) -> DgaFaultType {
    let ch4 = dga.methane_ch4_ppm.unwrap_or(0.0);
    let c2h4 = dga.ethylene_c2h4_ppm.unwrap_or(0.0);
    let c2h2 = dga.acetylene_c2h2_ppm.unwrap_or(0.0);

    let total = ch4 + c2h4 + c2h2;

    // If total hydrocarbon gases are very low, no significant fault
    if total < 10.0 {
        return DgaFaultType::Normal;
    }

    // Calculate percentages for Duval Triangle
    let pct_ch4 = (ch4 / total) * 100.0;
    let pct_c2h4 = (c2h4 / total) * 100.0;
    let pct_c2h2 = (c2h2 / total) * 100.0;

    // Duval Triangle zone classification
    // Zone boundaries based on IEC 60599

    // Check for PD zone first (high CH4, low C2H4, very low C2H2)
    if pct_c2h2 < 4.0 && pct_c2h4 < 20.0 && pct_ch4 > 98.0 {
        return DgaFaultType::PartialDischarge;
    }

    // Check for high energy discharge D2 (high C2H2)
    if pct_c2h2 > 29.0 {
        return DgaFaultType::HighEnergyDischarge;
    }

    // Check for low energy discharge D1
    if pct_c2h2 > 13.0 && pct_c2h2 <= 29.0 {
        return DgaFaultType::LowEnergyDischarge;
    }

    // Check for mixed fault DT
    if pct_c2h2 > 4.0 && pct_c2h2 <= 13.0 && pct_c2h4 > 20.0 {
        return DgaFaultType::MixedFault;
    }

    // Thermal fault classification based on C2H4 percentage
    if pct_c2h2 <= 4.0 {
        if pct_c2h4 < 20.0 {
            // T1 - Low temperature thermal fault
            return DgaFaultType::ThermalFaultLow;
        } else if pct_c2h4 < 50.0 {
            // T2 - Medium temperature thermal fault
            return DgaFaultType::ThermalFaultMedium;
        } else {
            // T3 - High temperature thermal fault
            return DgaFaultType::ThermalFaultHigh;
        }
    }

    // Check for stray gassing (elevated H2 with normal other gases)
    let h2 = dga.hydrogen_h2_ppm.unwrap_or(0.0);
    if h2 > 100.0 && c2h2 < 1.0 && c2h4 < 10.0 {
        return DgaFaultType::StrayGassing;
    }

    DgaFaultType::Normal
}

/// Assesses DGA status per IEEE C57.104-2019 guidelines
///
/// Uses individual gas concentration limits to determine overall status.
/// Returns the worst (highest) status based on all gas levels.
pub fn assess_dga_status(dga: &DgaAnalysis) -> DgaStatus {
    let mut worst_status = DgaStatus::Normal;

    // IEEE C57.104-2019 Table 1 - Typical gas concentrations (ppm)
    // Condition 1 (Normal) | Condition 2 | Condition 3 | Condition 4

    // Hydrogen (H2) limits: 100 | 200 | 500 | >500
    if let Some(h2) = dga.hydrogen_h2_ppm {
        let status = if h2 > 500.0 {
            DgaStatus::Critical
        } else if h2 > 200.0 {
            DgaStatus::Warning
        } else if h2 > 100.0 {
            DgaStatus::Caution
        } else {
            DgaStatus::Normal
        };
        if status > worst_status {
            worst_status = status;
        }
    }

    // Methane (CH4) limits: 75 | 125 | 400 | >400
    if let Some(ch4) = dga.methane_ch4_ppm {
        let status = if ch4 > 400.0 {
            DgaStatus::Critical
        } else if ch4 > 125.0 {
            DgaStatus::Warning
        } else if ch4 > 75.0 {
            DgaStatus::Caution
        } else {
            DgaStatus::Normal
        };
        if status > worst_status {
            worst_status = status;
        }
    }

    // Ethane (C2H6) limits: 65 | 100 | 200 | >200
    if let Some(c2h6) = dga.ethane_c2h6_ppm {
        let status = if c2h6 > 200.0 {
            DgaStatus::Critical
        } else if c2h6 > 100.0 {
            DgaStatus::Warning
        } else if c2h6 > 65.0 {
            DgaStatus::Caution
        } else {
            DgaStatus::Normal
        };
        if status > worst_status {
            worst_status = status;
        }
    }

    // Ethylene (C2H4) limits: 50 | 100 | 200 | >200
    if let Some(c2h4) = dga.ethylene_c2h4_ppm {
        let status = if c2h4 > 200.0 {
            DgaStatus::Critical
        } else if c2h4 > 100.0 {
            DgaStatus::Warning
        } else if c2h4 > 50.0 {
            DgaStatus::Caution
        } else {
            DgaStatus::Normal
        };
        if status > worst_status {
            worst_status = status;
        }
    }

    // Acetylene (C2H2) limits: 2 | 10 | 35 | >35
    // Acetylene is critical - any significant amount indicates arcing
    if let Some(c2h2) = dga.acetylene_c2h2_ppm {
        let status = if c2h2 > 35.0 {
            DgaStatus::Critical
        } else if c2h2 > 10.0 {
            DgaStatus::Warning
        } else if c2h2 > 2.0 {
            DgaStatus::Caution
        } else {
            DgaStatus::Normal
        };
        if status > worst_status {
            worst_status = status;
        }
    }

    // Carbon Monoxide (CO) limits: 400 | 600 | 1000 | >1000
    if let Some(co) = dga.carbon_monoxide_co_ppm {
        let status = if co > 1000.0 {
            DgaStatus::Critical
        } else if co > 600.0 {
            DgaStatus::Warning
        } else if co > 400.0 {
            DgaStatus::Caution
        } else {
            DgaStatus::Normal
        };
        if status > worst_status {
            worst_status = status;
        }
    }

    // Total Combustible Gas (TCG) limits: 720 | 1400 | 4630 | >4630
    let tcg = compute_tcg(dga);
    let status = if tcg > 4630.0 {
        DgaStatus::Critical
    } else if tcg > 1400.0 {
        DgaStatus::Warning
    } else if tcg > 720.0 {
        DgaStatus::Caution
    } else {
        DgaStatus::Normal
    };
    if status > worst_status {
        worst_status = status;
    }

    worst_status
}

/// Computes Total Combustible Gas (TCG) from DGA results
///
/// TCG = H2 + CH4 + C2H6 + C2H4 + C2H2 + CO
/// All values in ppm
pub fn compute_tcg(dga: &DgaAnalysis) -> f64 {
    let h2 = dga.hydrogen_h2_ppm.unwrap_or(0.0);
    let ch4 = dga.methane_ch4_ppm.unwrap_or(0.0);
    let c2h6 = dga.ethane_c2h6_ppm.unwrap_or(0.0);
    let c2h4 = dga.ethylene_c2h4_ppm.unwrap_or(0.0);
    let c2h2 = dga.acetylene_c2h2_ppm.unwrap_or(0.0);
    let co = dga.carbon_monoxide_co_ppm.unwrap_or(0.0);

    h2 + ch4 + c2h6 + c2h4 + c2h2 + co
}

/// Computes the CO2/CO ratio for cellulose degradation assessment
///
/// Ratio interpretation:
/// - > 10: Normal aging
/// - 3-10: Elevated thermal stress on cellulose
/// - < 3: Severe cellulose degradation
pub fn compute_co2_co_ratio(dga: &DgaAnalysis) -> Option<f64> {
    let co2 = dga.carbon_dioxide_co2_ppm?;
    let co = dga.carbon_monoxide_co_ppm?;

    if co > 0.0 {
        Some(co2 / co)
    } else {
        None
    }
}

/// Computes the C2H2/C2H4 ratio for fault severity assessment
///
/// Higher ratios indicate more severe electrical faults (arcing)
pub fn compute_c2h2_c2h4_ratio(dga: &DgaAnalysis) -> Option<f64> {
    let c2h2 = dga.acetylene_c2h2_ppm?;
    let c2h4 = dga.ethylene_c2h4_ppm?;

    if c2h4 > 0.0 {
        Some(c2h2 / c2h4)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn create_test_dga(h2: f64, ch4: f64, c2h6: f64, c2h4: f64, c2h2: f64, co: f64) -> DgaAnalysis {
        DgaAnalysis {
            id: Uuid::new_v4(),
            asset_id: Uuid::new_v4(),
            sample_date: Utc::now(),
            lab_reference: None,
            hydrogen_h2_ppm: Some(h2),
            methane_ch4_ppm: Some(ch4),
            ethane_c2h6_ppm: Some(c2h6),
            ethylene_c2h4_ppm: Some(c2h4),
            acetylene_c2h2_ppm: Some(c2h2),
            carbon_monoxide_co_ppm: Some(co),
            carbon_dioxide_co2_ppm: None,
            oxygen_o2_ppm: None,
            nitrogen_n2_ppm: None,
            total_combustible_gas_ppm: None,
            fault_type: None,
            status: None,
            assessment_method: None,
            test_report_number: None,
            result_summary: None,
            tested_by: None,
            workflow_state: None,
            recommendations: None,
            notes: None,
            created_at: None,
            created_by: None,
        }
    }

    #[test]
    fn test_tcg_computation() {
        let dga = create_test_dga(100.0, 50.0, 30.0, 20.0, 5.0, 200.0);
        let tcg = compute_tcg(&dga);
        assert!((tcg - 405.0).abs() < 0.001);
    }

    #[test]
    fn test_normal_status() {
        let dga = create_test_dga(50.0, 30.0, 20.0, 10.0, 0.5, 100.0);
        let status = assess_dga_status(&dga);
        assert_eq!(status, DgaStatus::Normal);
    }

    #[test]
    fn test_critical_acetylene() {
        let dga = create_test_dga(50.0, 30.0, 20.0, 10.0, 50.0, 100.0);
        let status = assess_dga_status(&dga);
        assert_eq!(status, DgaStatus::Critical);
    }

    #[test]
    fn test_high_energy_discharge_fault() {
        // High C2H2 indicates high energy discharge
        let dga = create_test_dga(100.0, 20.0, 10.0, 30.0, 40.0, 100.0);
        let fault = classify_dga_fault(&dga);
        assert_eq!(fault, DgaFaultType::HighEnergyDischarge);
    }

    #[test]
    fn test_thermal_fault_high() {
        // High C2H4 with low C2H2 indicates high temperature thermal fault
        let dga = create_test_dga(100.0, 30.0, 20.0, 150.0, 2.0, 100.0);
        let fault = classify_dga_fault(&dga);
        assert_eq!(fault, DgaFaultType::ThermalFaultHigh);
    }
}
