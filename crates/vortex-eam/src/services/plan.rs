//! Maintenance Plan Service
//!
//! Generates work orders from maintenance plans within their planning horizon.
//! Ported from SESB EAM Odoo module (eam_maintenance_plan.py).

use chrono::{NaiveDate, Utc, Months, Days};
use uuid::Uuid;

use vortex_common::{VortexResult, VortexError};
use vortex_orm::ConnectionPool;

use crate::services::sequence;

/// Maintenance Plan States
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanState {
    Draft,
    Active,
    Done,
    Cancelled,
}

impl PlanState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PlanState::Draft => "draft",
            PlanState::Active => "active",
            PlanState::Done => "done",
            PlanState::Cancelled => "cancelled",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "draft" => Some(PlanState::Draft),
            "active" => Some(PlanState::Active),
            "done" => Some(PlanState::Done),
            "cancelled" => Some(PlanState::Cancelled),
            _ => None,
        }
    }
}

/// Activate a maintenance plan (draft → active)
pub async fn activate_plan(
    pool: &ConnectionPool,
    plan_id: Uuid,
    user_id: Uuid,
) -> VortexResult<()> {
    let now = Utc::now();

    let rows = sqlx::query(
        r#"
        UPDATE eam_maintenance_plans
        SET state = 'active', is_active = TRUE, updated_at = $1, updated_by = $2
        WHERE id = $3 AND state = 'draft'
        "#
    )
        .bind(now)
        .bind(user_id)
        .bind(plan_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    if rows.rows_affected() == 0 {
        return Err(VortexError::ValidationFailed(
            "Plan not found or not in draft state".to_string(),
        ));
    }

    Ok(())
}

/// Cancel a maintenance plan
pub async fn cancel_plan(
    pool: &ConnectionPool,
    plan_id: Uuid,
    user_id: Uuid,
) -> VortexResult<()> {
    let now = Utc::now();

    let rows = sqlx::query(
        r#"
        UPDATE eam_maintenance_plans
        SET state = 'cancelled', is_active = FALSE, updated_at = $1, updated_by = $2
        WHERE id = $3 AND state IN ('draft', 'active')
        "#
    )
        .bind(now)
        .bind(user_id)
        .bind(plan_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    if rows.rows_affected() == 0 {
        return Err(VortexError::ValidationFailed(
            "Plan not found or already completed/cancelled".to_string(),
        ));
    }

    Ok(())
}

/// Generate planned work orders within the planning horizon.
///
/// Starting from the plan's `next_maintenance_date`, creates work orders at each
/// frequency interval until the planning horizon is reached.
///
/// Returns the number of work orders created.
pub async fn generate_planned_orders(
    pool: &ConnectionPool,
    plan_id: Uuid,
    user_id: Uuid,
) -> VortexResult<i64> {
    // Fetch plan details
    let plan: Option<(
        Option<String>,     // state
        Uuid,               // asset_id
        Uuid,               // company_id
        Option<String>,     // maintenance_type
        Option<i32>,        // priority
        Option<f64>,        // planned_duration_hours
        Option<Uuid>,       // assigned_to
        Option<Uuid>,       // checklist_template_id
        Option<String>,     // next_maintenance_date
        Option<i32>,        // frequency_interval
        Option<String>,     // frequency_unit
        Option<i32>,        // planning_horizon_interval
        Option<String>,     // planning_horizon_unit
        Option<String>,     // description
    )> = sqlx::query_as(
        r#"
        SELECT state, asset_id, company_id, maintenance_type, priority,
               planned_duration_hours, assigned_to, checklist_template_id,
               next_maintenance_date, frequency_interval, frequency_unit,
               planning_horizon_interval, planning_horizon_unit, description
        FROM eam_maintenance_plans
        WHERE id = $1
        "#
    )
        .bind(plan_id)
        .fetch_optional(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let (
        state, asset_id, company_id, maintenance_type, priority,
        planned_duration, assigned_to, checklist_template_id,
        next_date_str, freq_interval, freq_unit, horizon_interval, horizon_unit,
        description,
    ) = plan.ok_or_else(|| VortexError::ValidationFailed(
        "Maintenance plan not found".to_string(),
    ))?;

    // Validate state is active
    if state.as_deref() != Some("active") {
        return Err(VortexError::ValidationFailed(
            "Plan must be in 'active' state to generate orders".to_string(),
        ));
    }

    // Parse next maintenance date
    let next_date = next_date_str
        .as_deref()
        .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
        .ok_or_else(|| VortexError::ValidationFailed(
            "Plan has no valid next_maintenance_date".to_string(),
        ))?;

    let freq_int = freq_interval.unwrap_or(1);
    let freq_u = freq_unit.as_deref().unwrap_or("month");

    // Compute planning horizon end date
    let horizon_int = horizon_interval.unwrap_or(12);
    let horizon_u = horizon_unit.as_deref().unwrap_or("month");
    let today = Utc::now().date_naive();
    let horizon_end = add_interval(today, horizon_int, horizon_u);

    // Generate work orders from next_date up to horizon_end
    let mut current_date = next_date;
    let mut count = 0_i64;

    while current_date <= horizon_end {
        // Check if a work order already exists for this plan on this date
        let existing: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)::bigint FROM eam_work_orders
            WHERE plan_id = $1 AND scheduled_start::date = $2::date
            "#
        )
            .bind(plan_id)
            .bind(current_date.to_string())
            .fetch_one(pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        if existing.unwrap_or(0) == 0 {
            // Generate work order code
            let wo_code = sequence::next_maintenance_code(pool).await?;

            let wo_id = Uuid::new_v4();
            let title = format!(
                "Planned {} - {}",
                maintenance_type.as_deref().unwrap_or("maintenance"),
                description.as_deref().unwrap_or(&wo_code)
            );

            let scheduled_start = current_date
                .and_hms_opt(8, 0, 0)
                .unwrap()
                .and_utc();

            sqlx::query(
                r#"
                INSERT INTO eam_work_orders (
                    id, company_id, wo_number, asset_id, title, description,
                    maintenance_type, priority, planned_duration_hours,
                    state, scheduled_start, assigned_to,
                    checklist_template_id, plan_id, schedule_id,
                    created_at, created_by
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'draft', $10, $11, $12, $13, NULL, now(), $14)
                "#
            )
                .bind(wo_id)
                .bind(company_id)
                .bind(&wo_code)
                .bind(asset_id)
                .bind(&title)
                .bind(description.as_deref())
                .bind(maintenance_type.as_deref())
                .bind(priority)
                .bind(planned_duration)
                .bind(scheduled_start)
                .bind(assigned_to)
                .bind(checklist_template_id)
                .bind(plan_id)
                .bind(user_id)
                .execute(pool.pool())
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

            count += 1;
        }

        // Advance to next date
        current_date = add_interval(current_date, freq_int, freq_u);
    }

    // Update next_maintenance_date to the next date beyond horizon
    let next_date_str = current_date.format("%Y-%m-%d").to_string();
    sqlx::query(
        "UPDATE eam_maintenance_plans SET next_maintenance_date = $1, updated_at = now(), updated_by = $2 WHERE id = $3"
    )
        .bind(&next_date_str)
        .bind(user_id)
        .bind(plan_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(count)
}

/// Add an interval to a date based on unit (day, week, month, year)
fn add_interval(date: NaiveDate, interval: i32, unit: &str) -> NaiveDate {
    match unit {
        "day" => date + Days::new(interval as u64),
        "week" => date + Days::new((interval * 7) as u64),
        "month" => date + Months::new(interval as u32),
        "year" => date + Months::new((interval * 12) as u32),
        _ => date + Months::new(interval as u32), // default to months
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_state() {
        assert_eq!(PlanState::Draft.as_str(), "draft");
        assert_eq!(PlanState::Active.as_str(), "active");
        assert_eq!(PlanState::from_str("active"), Some(PlanState::Active));
        assert_eq!(PlanState::from_str("invalid"), None);
    }

    #[test]
    fn test_add_interval_days() {
        let date = NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();
        let result = add_interval(date, 30, "day");
        assert_eq!(result, NaiveDate::from_ymd_opt(2026, 2, 14).unwrap());
    }

    #[test]
    fn test_add_interval_weeks() {
        let date = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        let result = add_interval(date, 2, "week");
        assert_eq!(result, NaiveDate::from_ymd_opt(2026, 1, 15).unwrap());
    }

    #[test]
    fn test_add_interval_months() {
        let date = NaiveDate::from_ymd_opt(2026, 1, 31).unwrap();
        let result = add_interval(date, 3, "month");
        // chrono handles month-end gracefully
        assert_eq!(result, NaiveDate::from_ymd_opt(2026, 4, 30).unwrap());
    }

    #[test]
    fn test_add_interval_years() {
        let date = NaiveDate::from_ymd_opt(2026, 6, 15).unwrap();
        let result = add_interval(date, 1, "year");
        assert_eq!(result, NaiveDate::from_ymd_opt(2027, 6, 15).unwrap());
    }
}
