//! Health Index Computation Service
//!
//! Computes asset health index and probability of failure per SESB spec

/// Health Index Categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HealthCategory {
    /// Very Good (85-100): Asset in excellent condition
    VeryGood,
    /// Good (70-85): Asset in good condition, normal maintenance
    Good,
    /// Fair (50-70): Asset showing signs of deterioration
    Fair,
    /// Poor (30-50): Significant deterioration, increased monitoring
    Poor,
    /// Very Poor (0-30): Critical condition, intervention required
    VeryPoor,
}

impl HealthCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            HealthCategory::VeryGood => "very_good",
            HealthCategory::Good => "good",
            HealthCategory::Fair => "fair",
            HealthCategory::Poor => "poor",
            HealthCategory::VeryPoor => "very_poor",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            HealthCategory::VeryGood => "Very Good",
            HealthCategory::Good => "Good",
            HealthCategory::Fair => "Fair",
            HealthCategory::Poor => "Poor",
            HealthCategory::VeryPoor => "Very Poor",
        }
    }

    pub fn recommended_action(&self) -> &'static str {
        match self {
            HealthCategory::VeryGood => "Continue normal maintenance schedule",
            HealthCategory::Good => "Monitor with routine maintenance",
            HealthCategory::Fair => "Increase monitoring frequency, plan preventive maintenance",
            HealthCategory::Poor => "Schedule corrective maintenance, detailed assessment needed",
            HealthCategory::VeryPoor => "Immediate intervention required, consider replacement",
        }
    }
}

/// Computes Health Index from condition and operational status
///
/// Health Index = (Condition Weight × Condition Score) + (Operational Weight × Operational Score)
///
/// # Arguments
/// * `condition_status` - Condition status: good, acceptable, marginal, poor, critical
/// * `operational_status` - Operational status: in_service, standby, under_maintenance, faulty
///
/// # Returns
/// Health Index value from 0.0 to 100.0
pub fn compute(condition_status: &str, operational_status: &str) -> f64 {
    // Condition score (60% weight)
    let condition_score = match condition_status.to_lowercase().as_str() {
        "excellent" | "very_good" => 100.0,
        "good" => 85.0,
        "acceptable" | "satisfactory" => 70.0,
        "marginal" | "fair" => 50.0,
        "poor" => 30.0,
        "critical" | "very_poor" => 10.0,
        _ => 50.0, // Default to fair if unknown
    };

    // Operational score (40% weight)
    let operational_score = match operational_status.to_lowercase().as_str() {
        "in_service" | "active" | "operational" => 100.0,
        "standby" => 90.0,
        "under_maintenance" | "maintenance" => 70.0,
        "faulty" | "out_of_service" => 30.0,
        "decommissioned" | "retired" => 0.0,
        _ => 70.0, // Default if unknown
    };

    // Weighted calculation
    const CONDITION_WEIGHT: f64 = 0.6;
    const OPERATIONAL_WEIGHT: f64 = 0.4;

    (CONDITION_WEIGHT * condition_score) + (OPERATIONAL_WEIGHT * operational_score)
}

/// Computes Health Index from numeric scores
///
/// # Arguments
/// * `condition_score` - Condition score (0-100)
/// * `operational_score` - Operational score (0-100)
///
/// # Returns
/// Health Index value from 0.0 to 100.0
pub fn compute_from_scores(condition_score: f64, operational_score: f64) -> f64 {
    const CONDITION_WEIGHT: f64 = 0.6;
    const OPERATIONAL_WEIGHT: f64 = 0.4;

    let cond = condition_score.clamp(0.0, 100.0);
    let oper = operational_score.clamp(0.0, 100.0);

    (CONDITION_WEIGHT * cond) + (OPERATIONAL_WEIGHT * oper)
}

/// Categorizes a health index value
///
/// # Arguments
/// * `health_index` - Health index value (0-100)
///
/// # Returns
/// Health category as string
pub fn categorize(health_index: f64) -> HealthCategory {
    if health_index >= 85.0 {
        HealthCategory::VeryGood
    } else if health_index >= 70.0 {
        HealthCategory::Good
    } else if health_index >= 50.0 {
        HealthCategory::Fair
    } else if health_index >= 30.0 {
        HealthCategory::Poor
    } else {
        HealthCategory::VeryPoor
    }
}

/// Computes probability of failure based on health index and age
///
/// Uses a simplified Weibull-based model where probability increases
/// with declining health and asset age relative to design life.
///
/// # Arguments
/// * `health_index` - Health index value (0-100)
/// * `age_years` - Current age of asset in years
/// * `design_life_years` - Design life of asset in years
///
/// # Returns
/// Probability of failure (0.0 to 1.0)
pub fn probability_of_failure(health_index: f64, age_years: i32, design_life_years: i32) -> f64 {
    // Health factor: lower health = higher failure probability
    // HI of 100 = 0% contribution, HI of 0 = 50% contribution
    let health_factor = (100.0 - health_index) / 200.0;

    // Age factor: older assets relative to design life have higher probability
    // At design life = 30% contribution, at 2x design life = 50% contribution
    let age_ratio = if design_life_years > 0 {
        (age_years as f64) / (design_life_years as f64)
    } else {
        0.5 // Default if design life unknown
    };

    // Weibull-like shape: probability increases more steeply after design life
    let age_factor = if age_ratio <= 1.0 {
        // Before end of design life: gradual increase
        age_ratio * 0.3
    } else {
        // After design life: steeper increase
        0.3 + (age_ratio - 1.0).min(1.0) * 0.2
    };

    // Combined probability (capped at 0.95)
    let pof = health_factor + age_factor;
    pof.clamp(0.0, 0.95)
}

/// Computes risk score (Health Index × Criticality × Consequence)
///
/// # Arguments
/// * `health_index` - Health index value (0-100)
/// * `criticality_rating` - Asset criticality (1-5, where 5 is most critical)
///
/// # Returns
/// Risk score (higher = more risk)
pub fn compute_risk_score(health_index: f64, criticality_rating: i32) -> f64 {
    // Invert health index so lower health = higher risk contribution
    let health_risk = (100.0 - health_index) / 100.0;

    // Criticality factor (1-5 scale, normalized to 0.2-1.0)
    let criticality_factor = (criticality_rating as f64) / 5.0;

    // Risk = (1 - normalized_health) × criticality
    // Scale to 0-100 for easier interpretation
    health_risk * criticality_factor * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_health_index() {
        // Good condition, in service = high HI
        let hi = compute("good", "in_service");
        assert!(hi > 80.0);

        // Poor condition, faulty = low HI
        let hi = compute("poor", "faulty");
        assert!(hi < 40.0);

        // Critical condition = very low HI
        let hi = compute("critical", "in_service");
        assert!(hi < 50.0);
    }

    #[test]
    fn test_categorize() {
        assert_eq!(categorize(90.0), HealthCategory::VeryGood);
        assert_eq!(categorize(75.0), HealthCategory::Good);
        assert_eq!(categorize(60.0), HealthCategory::Fair);
        assert_eq!(categorize(40.0), HealthCategory::Poor);
        assert_eq!(categorize(20.0), HealthCategory::VeryPoor);
    }

    #[test]
    fn test_probability_of_failure() {
        // New asset with good health = low PoF
        let pof = probability_of_failure(90.0, 5, 30);
        assert!(pof < 0.2);

        // Old asset past design life with poor health = high PoF
        let pof = probability_of_failure(30.0, 40, 30);
        assert!(pof > 0.5);

        // PoF should never exceed 0.95
        let pof = probability_of_failure(0.0, 100, 30);
        assert!(pof <= 0.95);
    }

    #[test]
    fn test_risk_score() {
        // Low health, high criticality = high risk
        let risk = compute_risk_score(20.0, 5);
        assert!(risk > 60.0);

        // High health, low criticality = low risk
        let risk = compute_risk_score(90.0, 1);
        assert!(risk < 5.0);
    }
}
