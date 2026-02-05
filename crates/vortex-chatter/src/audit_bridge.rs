//! Bridge between vortex-security audit log and chatter display

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
use vortex_common::{Context, UserId, VortexError, VortexResult};
use vortex_orm::ConnectionPool;
use vortex_security::AuditLog;

fn map_db_err(e: sqlx::Error) -> VortexError {
    VortexError::QueryExecution(e.to_string())
}

/// Bridge between existing audit system and chatter display.
pub struct AuditBridge {
    pool: Arc<ConnectionPool>,
    audit: Arc<AuditLog>,
}

impl AuditBridge {
    pub fn new(pool: Arc<ConnectionPool>, audit: Arc<AuditLog>) -> Self {
        Self { pool, audit }
    }

    /// Get audit entries for a specific record, formatted for chatter display.
    pub async fn get_audit_for_record(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        limit: u64,
        offset: u64,
    ) -> VortexResult<Vec<ChatterAuditEntry>> {
        // Query audit_log table directly for this resource
        let entries = sqlx::query_as::<_, AuditRow>(
            r#"
            SELECT id, timestamp, action, user_id, details, resource_type, resource_id
            FROM audit_log
            WHERE resource_type = $1 AND resource_id = $2
            ORDER BY timestamp DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(res_model)
        .bind(res_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(self.pool.pool())
        .await.map_err(map_db_err)?;

        let chatter_entries: Vec<ChatterAuditEntry> = entries
            .into_iter()
            .map(|e| self.convert_audit_row(e))
            .collect();

        Ok(chatter_entries)
    }

    fn convert_audit_row(&self, row: AuditRow) -> ChatterAuditEntry {
        // Extract field changes from details JSON
        let changes = self.extract_changes_from_details(&row.details);

        ChatterAuditEntry {
            id: row.id,
            timestamp: row.timestamp,
            action: row.action,
            user_id: row.user_id.map(UserId),
            changes,
        }
    }

    fn extract_changes_from_details(&self, details: &Option<Value>) -> Vec<FieldChangeDisplay> {
        let mut changes = Vec::new();

        if let Some(Value::Object(obj)) = details {
            // Look for "changes" array in details
            if let Some(Value::Array(change_list)) = obj.get("changes") {
                for change in change_list {
                    if let Value::Object(c) = change {
                        let field = c
                            .get("field")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let old_value = c.get("old").map(format_value);
                        let new_value = c.get("new").map(format_value);

                        changes.push(FieldChangeDisplay {
                            field,
                            old_value,
                            new_value,
                        });
                    }
                }
            }

            // Also check for "previous_state" and "new_state" pattern
            if let (Some(prev), Some(new)) = (obj.get("previous_state"), obj.get("new_state")) {
                if let (Some(prev_obj), Some(new_obj)) = (prev.as_object(), new.as_object()) {
                    for (key, new_val) in new_obj {
                        let old_val = prev_obj.get(key);
                        if old_val != Some(new_val) {
                            changes.push(FieldChangeDisplay {
                                field: key.clone(),
                                old_value: old_val.map(format_value),
                                new_value: Some(format_value(new_val)),
                            });
                        }
                    }
                }
            }
        }

        changes
    }
}

/// Audit entry formatted for chatter display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatterAuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub user_id: Option<UserId>,
    pub changes: Vec<FieldChangeDisplay>,
}

/// Field change for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChangeDisplay {
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Internal audit row from database.
#[derive(sqlx::FromRow)]
struct AuditRow {
    id: Uuid,
    timestamp: DateTime<Utc>,
    action: String,
    user_id: Option<Uuid>,
    details: Option<Value>,
    resource_type: Option<String>,
    resource_id: Option<Uuid>,
}

fn format_value(v: &Value) -> String {
    match v {
        Value::Null => "(empty)".to_string(),
        Value::Bool(b) => if *b { "Yes" } else { "No" }.to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Array(arr) => format!("[{} items]", arr.len()),
        Value::Object(_) => "[object]".to_string(),
    }
}
