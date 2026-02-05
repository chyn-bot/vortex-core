//! Checklist Service
//!
//! Generates checklist lines from templates, computes progress and scores.
//! Ported from SESB EAM Odoo module (eam_checklist_line.py scoring logic).

use uuid::Uuid;

use vortex_common::{VortexResult, VortexError};
use vortex_orm::ConnectionPool;

/// Checklist progress summary for a work order
#[derive(Debug, Clone)]
pub struct ChecklistProgress {
    pub total: i64,
    pub completed: i64,
    pub progress_percent: f64,
}

/// Checklist score summary for a work order
#[derive(Debug, Clone)]
pub struct ChecklistScore {
    pub score: f64,
    pub result: ChecklistResult,
    pub has_critical_failure: bool,
}

/// Overall checklist result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecklistResult {
    Pass,
    Fail,
    Incomplete,
}

impl ChecklistResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChecklistResult::Pass => "pass",
            ChecklistResult::Fail => "fail",
            ChecklistResult::Incomplete => "incomplete",
        }
    }
}

/// Generate checklist lines for a work order from a template.
///
/// Copies all template items into checklist lines linked to the work order.
/// Returns the number of lines created.
pub async fn generate_checklist_lines(
    pool: &ConnectionPool,
    work_order_id: Uuid,
    template_id: Uuid,
) -> VortexResult<i64> {
    // Verify template exists and is active
    let active: Option<bool> = sqlx::query_scalar(
        "SELECT is_active FROM eam_checklist_templates WHERE id = $1"
    )
        .bind(template_id)
        .fetch_optional(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    match active {
        None => return Err(VortexError::ValidationFailed(
            "Checklist template not found".to_string(),
        )),
        Some(false) => return Err(VortexError::ValidationFailed(
            "Checklist template is not active".to_string(),
        )),
        _ => {}
    }

    // Delete any existing checklist lines for this work order (regeneration)
    sqlx::query("DELETE FROM eam_checklist_lines WHERE work_order_id = $1")
        .bind(work_order_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    // Copy template items to checklist lines
    let result = sqlx::query(
        r#"
        INSERT INTO eam_checklist_lines (
            id, work_order_id, template_item_id,
            name, description, sequence, section, input_type,
            measurement_unit, measurement_min, measurement_max,
            selection_options, rating_scale_max,
            is_required, is_critical, is_scored, weight,
            is_completed, is_failed, is_out_of_range, measurement_filled
        )
        SELECT
            gen_random_uuid(), $1, ti.id,
            ti.name, ti.description, ti.sequence, ti.section, ti.input_type,
            ti.measurement_unit, ti.measurement_min, ti.measurement_max,
            ti.selection_options, ti.rating_scale_max,
            ti.is_required, ti.is_critical, ti.is_scored, ti.weight,
            FALSE, FALSE, FALSE, FALSE
        FROM eam_checklist_template_items ti
        WHERE ti.template_id = $2
        ORDER BY ti.sequence
        "#
    )
        .bind(work_order_id)
        .bind(template_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    // Update work order with template reference
    sqlx::query(
        "UPDATE eam_work_orders SET checklist_template_id = $1 WHERE id = $2"
    )
        .bind(template_id)
        .bind(work_order_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(result.rows_affected() as i64)
}

/// Compute checklist progress for a work order
pub async fn compute_checklist_progress(
    pool: &ConnectionPool,
    work_order_id: Uuid,
) -> VortexResult<ChecklistProgress> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        r#"
        SELECT
            COUNT(*)::bigint AS total,
            COUNT(*) FILTER (WHERE is_completed = TRUE)::bigint AS completed
        FROM eam_checklist_lines
        WHERE work_order_id = $1
        "#
    )
        .bind(work_order_id)
        .fetch_optional(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let (total, completed) = row.unwrap_or((0, 0));
    let progress_percent = if total > 0 {
        (completed as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    Ok(ChecklistProgress {
        total,
        completed,
        progress_percent,
    })
}

/// Compute checklist score for a work order
///
/// Scoring logic per SESB spec:
/// - pass_fail: pass=100, fail=0, na=100
/// - yes_no: yes=100, no=0
/// - measurement: 100 if in range, 0 if out of range
/// - text: 100 if filled, 0 if empty
/// - selection: score_value from selected option (looked up in selection_options JSON)
/// - rating: (value / max) * 100
pub async fn compute_checklist_score(
    pool: &ConnectionPool,
    work_order_id: Uuid,
) -> VortexResult<ChecklistScore> {
    // Fetch all scored lines
    let rows: Vec<(
        Option<bool>,      // is_scored
        Option<f64>,       // weight
        Option<f64>,       // line_score
        Option<bool>,      // is_critical
        Option<bool>,      // is_failed
    )> = sqlx::query_as(
        r#"
        SELECT is_scored, weight, line_score, is_critical, is_failed
        FROM eam_checklist_lines
        WHERE work_order_id = $1
        "#
    )
        .bind(work_order_id)
        .fetch_all(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    if rows.is_empty() {
        return Ok(ChecklistScore {
            score: 0.0,
            result: ChecklistResult::Incomplete,
            has_critical_failure: false,
        });
    }

    let mut total_weight = 0.0_f64;
    let mut weighted_score = 0.0_f64;
    let mut has_critical_failure = false;
    let mut all_scored = true;

    for (is_scored, weight, line_score, is_critical, is_failed) in &rows {
        let scored = is_scored.unwrap_or(true);
        if !scored {
            continue;
        }

        let w = weight.unwrap_or(1.0);
        match line_score {
            Some(score) => {
                total_weight += w;
                weighted_score += score * w;
            }
            None => {
                all_scored = false;
            }
        }

        if is_critical.unwrap_or(false) && is_failed.unwrap_or(false) {
            has_critical_failure = true;
        }
    }

    let score = if total_weight > 0.0 {
        weighted_score / total_weight
    } else {
        0.0
    };

    let result = if has_critical_failure {
        ChecklistResult::Fail
    } else if !all_scored {
        ChecklistResult::Incomplete
    } else if score >= 70.0 {
        ChecklistResult::Pass
    } else {
        ChecklistResult::Fail
    };

    Ok(ChecklistScore {
        score,
        result,
        has_critical_failure,
    })
}

/// Score a single checklist line based on its input type and value.
///
/// Updates is_completed, line_score, is_out_of_range, is_failed in the database.
pub async fn score_checklist_line(
    pool: &ConnectionPool,
    line_id: Uuid,
) -> VortexResult<f64> {
    // Fetch the line
    let row: Option<(
        String,            // input_type
        Option<String>,    // value_pass_fail
        Option<String>,    // value_yes_no
        Option<f64>,       // value_measurement
        Option<String>,    // value_text
        Option<String>,    // value_selection
        Option<i32>,       // value_rating
        Option<f64>,       // measurement_min
        Option<f64>,       // measurement_max
        Option<i32>,       // rating_scale_max
        Option<serde_json::Value>, // selection_options
        Option<bool>,      // measurement_filled
    )> = sqlx::query_as(
        r#"
        SELECT input_type, value_pass_fail, value_yes_no, value_measurement,
               value_text, value_selection, value_rating,
               measurement_min, measurement_max, rating_scale_max,
               selection_options, measurement_filled
        FROM eam_checklist_lines
        WHERE id = $1
        "#
    )
        .bind(line_id)
        .fetch_optional(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let (
        input_type, value_pf, value_yn, value_meas, value_text, value_sel,
        value_rating, meas_min, meas_max, rating_max, sel_options, meas_filled,
    ) = row.ok_or_else(|| VortexError::ValidationFailed(
        "Checklist line not found".to_string(),
    ))?;

    let (score, is_completed, is_out_of_range, is_failed) = match input_type.as_str() {
        "pass_fail" => {
            match value_pf.as_deref() {
                Some("pass") => (100.0, true, false, false),
                Some("fail") => (0.0, true, false, true),
                Some("na") => (100.0, true, false, false),
                _ => (0.0, false, false, false),
            }
        }
        "yes_no" => {
            match value_yn.as_deref() {
                Some("yes") => (100.0, true, false, false),
                Some("no") => (0.0, true, false, true),
                _ => (0.0, false, false, false),
            }
        }
        "measurement" => {
            let filled = meas_filled.unwrap_or(false) || value_meas.is_some();
            if filled {
                let val = value_meas.unwrap_or(0.0);
                let in_range = match (meas_min, meas_max) {
                    (Some(min), Some(max)) => val >= min && val <= max,
                    (Some(min), None) => val >= min,
                    (None, Some(max)) => val <= max,
                    (None, None) => true,
                };
                let oor = !in_range;
                let score = if in_range { 100.0 } else { 0.0 };
                (score, true, oor, oor)
            } else {
                (0.0, false, false, false)
            }
        }
        "text" => {
            let filled = value_text.as_ref().map(|t| !t.trim().is_empty()).unwrap_or(false);
            let score = if filled { 100.0 } else { 0.0 };
            (score, filled, false, false)
        }
        "selection" => {
            match value_sel.as_deref() {
                Some(selected) => {
                    // Look up score_value from selection_options JSON
                    let score_val = sel_options
                        .as_ref()
                        .and_then(|opts| opts.as_array())
                        .and_then(|arr| {
                            arr.iter().find(|opt| {
                                opt.get("value")
                                    .and_then(|v| v.as_str())
                                    .map(|v| v == selected)
                                    .unwrap_or(false)
                            })
                        })
                        .and_then(|opt| opt.get("score_value").and_then(|s| s.as_f64()))
                        .unwrap_or(0.0);
                    let is_fail = sel_options
                        .as_ref()
                        .and_then(|opts| opts.as_array())
                        .and_then(|arr| {
                            arr.iter().find(|opt| {
                                opt.get("value")
                                    .and_then(|v| v.as_str())
                                    .map(|v| v == selected)
                                    .unwrap_or(false)
                            })
                        })
                        .and_then(|opt| opt.get("is_fail").and_then(|f| f.as_bool()))
                        .unwrap_or(false);
                    (score_val, true, false, is_fail)
                }
                None => (0.0, false, false, false),
            }
        }
        "rating" => {
            match value_rating {
                Some(val) => {
                    let max = rating_max.unwrap_or(5) as f64;
                    let score = if max > 0.0 { (val as f64 / max) * 100.0 } else { 0.0 };
                    (score, true, false, false)
                }
                None => (0.0, false, false, false),
            }
        }
        _ => (0.0, false, false, false),
    };

    // Update the line
    sqlx::query(
        r#"
        UPDATE eam_checklist_lines
        SET line_score = $1, is_completed = $2, is_out_of_range = $3, is_failed = $4,
            updated_at = now()
        WHERE id = $5
        "#
    )
        .bind(score)
        .bind(is_completed)
        .bind(is_out_of_range)
        .bind(is_failed)
        .bind(line_id)
        .execute(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checklist_result_display() {
        assert_eq!(ChecklistResult::Pass.as_str(), "pass");
        assert_eq!(ChecklistResult::Fail.as_str(), "fail");
        assert_eq!(ChecklistResult::Incomplete.as_str(), "incomplete");
    }
}
