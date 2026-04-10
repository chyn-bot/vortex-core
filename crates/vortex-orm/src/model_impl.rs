//! ModelExt and SecureModelExt implementations
//!
//! Provides the actual database operations for all Model types:
//! - find() / find_all() / save() / delete()
//! - Secure variants with access control enforcement
//! - Cache integration for read operations

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use sqlx::{postgres::PgRow, Row};
use tracing::debug;
use uuid::Uuid;

use crate::cache::RecordKey;
use crate::connection::ConnectionPool;
use crate::field::FieldType;
use crate::model::{AccessControl, Model, ModelExt, ModelMeta, SecureModelExt};
use crate::query::Filter;
use vortex_common::error::RecordId;
use vortex_common::{CompanyId, Context, FieldValue, VortexError, VortexResult};

// ─────────────────────────────────────────────────────────────────────────────
// FieldValue ↔ sqlx binding helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Bind a FieldValue to a sqlx query at the given position.
/// Returns a query with the value bound.
fn bind_field_value<'q>(
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    value: &'q FieldValue,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    match value {
        FieldValue::Null => query.bind(None::<String>),
        FieldValue::Bool(v) => query.bind(v),
        FieldValue::Int(v) => query.bind(v),
        FieldValue::Float(v) => query.bind(v),
        FieldValue::String(v) => query.bind(v.as_str()),
        FieldValue::Uuid(v) => query.bind(v),
        FieldValue::Timestamp(v) => query.bind(v),
        FieldValue::Json(v) => query.bind(v),
        FieldValue::Binary(v) => query.bind(v.as_slice()),
        FieldValue::Array(_) => query.bind(None::<String>), // Arrays need special handling
    }
}

/// Bind a FieldValue to a sqlx query_scalar.
fn bind_field_value_scalar<'q, T: sqlx::Type<sqlx::Postgres> + Send>(
    query: sqlx::query::QueryScalar<'q, sqlx::Postgres, T, sqlx::postgres::PgArguments>,
    value: &'q FieldValue,
) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, T, sqlx::postgres::PgArguments> {
    match value {
        FieldValue::Null => query.bind(None::<String>),
        FieldValue::Bool(v) => query.bind(v),
        FieldValue::Int(v) => query.bind(v),
        FieldValue::Float(v) => query.bind(v),
        FieldValue::String(v) => query.bind(v.as_str()),
        FieldValue::Uuid(v) => query.bind(v),
        FieldValue::Timestamp(v) => query.bind(v),
        FieldValue::Json(v) => query.bind(v),
        FieldValue::Binary(v) => query.bind(v.as_slice()),
        FieldValue::Array(_) => query.bind(None::<String>),
    }
}

/// Extract a FieldValue from a PgRow column.
fn row_to_field_value(row: &PgRow, col_name: &str, field_type: &FieldType) -> FieldValue {
    // Try to extract based on field type, fall back to null on error
    match field_type {
        FieldType::Boolean => row
            .try_get::<Option<bool>, _>(col_name)
            .ok()
            .flatten()
            .map(FieldValue::Bool)
            .unwrap_or(FieldValue::Null),
        FieldType::Integer => row
            .try_get::<Option<i32>, _>(col_name)
            .ok()
            .flatten()
            .map(|v| FieldValue::Int(v as i64))
            .unwrap_or(FieldValue::Null),
        FieldType::BigInt | FieldType::Serial => row
            .try_get::<Option<i64>, _>(col_name)
            .ok()
            .flatten()
            .map(FieldValue::Int)
            .unwrap_or(FieldValue::Null),
        FieldType::Float => row
            .try_get::<Option<f32>, _>(col_name)
            .ok()
            .flatten()
            .map(|v| FieldValue::Float(v as f64))
            .unwrap_or(FieldValue::Null),
        FieldType::Double | FieldType::Decimal { .. } => row
            .try_get::<Option<f64>, _>(col_name)
            .ok()
            .flatten()
            .map(FieldValue::Float)
            .unwrap_or(FieldValue::Null),
        FieldType::Uuid => row
            .try_get::<Option<Uuid>, _>(col_name)
            .ok()
            .flatten()
            .map(FieldValue::Uuid)
            .unwrap_or(FieldValue::Null),
        FieldType::Timestamp => row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(col_name)
            .ok()
            .flatten()
            .map(FieldValue::Timestamp)
            .unwrap_or(FieldValue::Null),
        FieldType::Date => row
            .try_get::<Option<String>, _>(col_name)
            .ok()
            .flatten()
            .map(FieldValue::String)
            .unwrap_or(FieldValue::Null),
        FieldType::Time => row
            .try_get::<Option<String>, _>(col_name)
            .ok()
            .flatten()
            .map(FieldValue::String)
            .unwrap_or(FieldValue::Null),
        FieldType::Json => row
            .try_get::<Option<serde_json::Value>, _>(col_name)
            .ok()
            .flatten()
            .map(FieldValue::Json)
            .unwrap_or(FieldValue::Null),
        FieldType::Binary => row
            .try_get::<Option<Vec<u8>>, _>(col_name)
            .ok()
            .flatten()
            .map(FieldValue::Binary)
            .unwrap_or(FieldValue::Null),
        FieldType::Computed => FieldValue::Null, // Computed fields not stored
        FieldType::Reference { .. } => {
            // Foreign keys are UUIDs
            row.try_get::<Option<Uuid>, _>(col_name)
                .ok()
                .flatten()
                .map(FieldValue::Uuid)
                .unwrap_or(FieldValue::Null)
        }
        FieldType::Enum { .. } | FieldType::String { .. } | FieldType::Text => row
            .try_get::<Option<String>, _>(col_name)
            .ok()
            .flatten()
            .map(FieldValue::String)
            .unwrap_or(FieldValue::Null),
        FieldType::Array(_) => FieldValue::Null, // TODO: Array extraction
    }
}

/// Convert a PgRow into a HashMap<String, FieldValue> using model metadata.
fn row_to_values(row: &PgRow, meta: &ModelMeta) -> HashMap<String, FieldValue> {
    let mut values = HashMap::new();
    for field_def in meta.fields_ordered() {
        if matches!(field_def.field_type, FieldType::Computed) {
            continue;
        }
        let col_name = field_def.column_name();
        let value = row_to_field_value(row, col_name, &field_def.field_type);
        values.insert(field_def.name.clone(), value);
    }
    values
}

/// Build a RecordKey from model metadata and primary key value.
fn make_cache_key(meta: &ModelMeta, pk: &FieldValue, company_id: Option<&CompanyId>) -> RecordKey {
    let pk_str = match pk {
        FieldValue::Uuid(u) => u.to_string(),
        FieldValue::Int(i) => i.to_string(),
        FieldValue::String(s) => s.clone(),
        _ => format!("{:?}", pk),
    };
    let mut key = RecordKey::new(&meta.name, pk_str);
    if let Some(cid) = company_id {
        key = key.with_company(cid.0.to_string());
    }
    key
}

// ─────────────────────────────────────────────────────────────────────────────
// SQL generation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generate INSERT SQL and collect values in column order.
fn build_insert_sql(
    meta: &ModelMeta,
    values: &HashMap<String, FieldValue>,
) -> (String, Vec<FieldValue>) {
    let mut columns = Vec::new();
    let mut placeholders = Vec::new();
    let mut params = Vec::new();
    let mut idx = 1;

    for field_def in meta.fields_ordered() {
        if matches!(field_def.field_type, FieldType::Computed) {
            continue;
        }
        let col_name = field_def.column_name();
        if let Some(value) = values.get(&field_def.name) {
            columns.push(col_name.to_string());
            placeholders.push(format!("${}", idx));
            params.push(value.clone());
            idx += 1;
        }
    }

    let sql = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
        meta.table,
        columns.join(", "),
        placeholders.join(", ")
    );

    (sql, params)
}

/// Generate UPDATE SQL for changed fields.
fn build_update_sql(
    meta: &ModelMeta,
    values: &HashMap<String, FieldValue>,
    pk_value: &FieldValue,
) -> (String, Vec<FieldValue>) {
    let mut set_clauses = Vec::new();
    let mut params = Vec::new();
    let mut idx = 1;

    for field_def in meta.fields_ordered() {
        if matches!(field_def.field_type, FieldType::Computed) {
            continue;
        }
        if field_def.primary_key {
            continue; // Don't update the PK
        }
        if field_def.readonly {
            continue; // Don't update readonly fields
        }
        let col_name = field_def.column_name();
        if let Some(value) = values.get(&field_def.name) {
            set_clauses.push(format!("{} = ${}", col_name, idx));
            params.push(value.clone());
            idx += 1;
        }
    }

    // Add PK as the last parameter for the WHERE clause
    params.push(pk_value.clone());

    let sql = format!(
        "UPDATE {} SET {} WHERE {} = ${}",
        meta.table,
        set_clauses.join(", "),
        meta.primary_key,
        idx
    );

    (sql, params)
}

/// Check if a record with this PK already exists.
async fn record_exists(
    pool: &ConnectionPool,
    meta: &ModelMeta,
    pk_value: &FieldValue,
) -> VortexResult<bool> {
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE {} = $1) AS exists",
        meta.table, meta.primary_key
    );

    let db = pool.pool();
    let mut query = sqlx::query_scalar::<_, bool>(&sql);
    query = bind_field_value_scalar(query, pk_value);

    query
        .fetch_one(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// ModelExt implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl<M: Model> ModelExt for M {
    async fn find(
        pool: &ConnectionPool,
        ctx: &Context,
        pk: impl Into<FieldValue> + Send,
    ) -> VortexResult<Option<Self>> {
        let meta = M::meta();
        let pk_value = pk.into();
        let dialect = pool.dialect();

        // Build SELECT query with tenant filter
        let mut sql = format!(
            "SELECT {} FROM {} WHERE {} = $1",
            meta.select_columns().join(", "),
            meta.table,
            meta.primary_key,
        );
        let mut params: Vec<FieldValue> = vec![pk_value.clone()];
        let mut param_idx = 2;

        // Add multi-tenant filter if applicable
        if meta.multi_tenant {
            if let Some(company_id) = &ctx.company_id {
                sql.push_str(&format!(" AND company_id = ${}", param_idx));
                params.push(FieldValue::Uuid(company_id.0));
                param_idx += 1;
            }
        }

        // Add soft-delete filter
        if meta.soft_delete {
            sql.push_str(" AND deleted_at IS NULL");
        }

        debug!(model = %meta.name, table = %meta.table, "ModelExt::find");

        let db = pool.pool();
        let mut query = sqlx::query(&sql);
        for p in &params {
            query = bind_field_value(query, p);
        }

        let row_opt = query
            .fetch_optional(db)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        match row_opt {
            Some(row) => {
                let values = row_to_values(&row, meta);
                let model = M::from_values(values)?;
                Ok(Some(model))
            }
            None => Ok(None),
        }
    }

    async fn find_all(
        pool: &ConnectionPool,
        ctx: &Context,
        filter: Filter,
    ) -> VortexResult<Vec<Self>> {
        let meta = M::meta();
        let dialect = pool.dialect();

        // Start building WHERE conditions
        let mut conditions = Vec::new();
        let mut params: Vec<FieldValue> = Vec::new();
        let mut param_idx = 1;

        // Add the user-provided filter
        if !matches!(&filter, Filter::Raw(s, _) if s.is_empty()) {
            let (filter_sql, filter_params) = filter.to_sql_with_dialect(dialect, &mut param_idx);
            if !filter_sql.is_empty() {
                conditions.push(filter_sql);
                params.extend(filter_params);
            }
        }

        // Add multi-tenant filter
        if meta.multi_tenant {
            if let Some(company_id) = &ctx.company_id {
                conditions.push(format!("company_id = ${}", param_idx));
                params.push(FieldValue::Uuid(company_id.0));
                param_idx += 1;
            }
        }

        // Add soft-delete filter
        if meta.soft_delete {
            conditions.push("deleted_at IS NULL".to_string());
        }

        let mut sql = format!(
            "SELECT {} FROM {}",
            meta.select_columns().join(", "),
            meta.table,
        );

        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }

        // Default ordering by created_at DESC if the field exists
        if meta.fields.contains_key("created_at") {
            sql.push_str(" ORDER BY created_at DESC NULLS LAST");
        }

        debug!(model = %meta.name, table = %meta.table, "ModelExt::find_all");

        let db = pool.pool();
        let mut query = sqlx::query(&sql);
        for p in &params {
            query = bind_field_value(query, p);
        }

        let rows = query
            .fetch_all(db)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        let mut results = Vec::with_capacity(rows.len());
        for row in &rows {
            let values = row_to_values(row, meta);
            let model = M::from_values(values)?;
            results.push(model);
        }

        Ok(results)
    }

    async fn save(
        &mut self,
        pool: &ConnectionPool,
        ctx: &Context,
    ) -> VortexResult<()> {
        let meta = M::meta();
        let pk_value = self.pk();

        // Validate before saving
        self.validate(ctx)?;

        // Compute derived fields
        self.compute_fields(ctx)?;

        let values = self.to_values();
        let is_new = matches!(&pk_value, FieldValue::Null)
            || !record_exists(pool, meta, &pk_value).await?;

        if is_new {
            // INSERT
            self.before_insert(ctx).await?;

            let (sql, params) = build_insert_sql(meta, &values);
            debug!(model = %meta.name, table = %meta.table, "ModelExt::save (INSERT)");

            let db = pool.pool();
            let mut query = sqlx::query(&sql);
            for p in &params {
                query = bind_field_value(query, p);
            }

            let row = query
                .fetch_one(db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

            // Update self from the returned row (gets DB defaults, generated values)
            let returned_values = row_to_values(&row, meta);
            *self = M::from_values(returned_values)?;

            self.after_insert(ctx).await?;
        } else {
            // UPDATE
            self.before_update(ctx).await?;

            let (sql, params) = build_update_sql(meta, &values, &pk_value);
            debug!(model = %meta.name, table = %meta.table, "ModelExt::save (UPDATE)");

            let db = pool.pool();
            let mut query = sqlx::query(&sql);
            for p in &params {
                query = bind_field_value(query, p);
            }

            let result = query
                .execute(db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

            if result.rows_affected() == 0 {
                return Err(VortexError::RecordNotFound {
                    model: meta.name.clone(),
                    id: field_value_to_record_id(&pk_value),
                });
            }

            self.after_update(ctx).await?;
        }

        Ok(())
    }

    async fn delete(
        self,
        pool: &ConnectionPool,
        ctx: &Context,
    ) -> VortexResult<()> {
        let meta = M::meta();
        let pk_value = self.pk();

        self.before_delete(ctx).await?;

        let db = pool.pool();

        if meta.soft_delete {
            // Soft delete: SET deleted_at = NOW()
            let sql = format!(
                "UPDATE {} SET deleted_at = NOW() WHERE {} = $1",
                meta.table, meta.primary_key,
            );
            debug!(model = %meta.name, table = %meta.table, "ModelExt::delete (soft)");

            let mut query = sqlx::query(&sql);
            query = bind_field_value(query, &pk_value);

            let result = query
                .execute(db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

            if result.rows_affected() == 0 {
                return Err(VortexError::RecordNotFound {
                    model: meta.name.clone(),
                    id: field_value_to_record_id(&pk_value),
                });
            }
        } else {
            // Hard delete
            let sql = format!(
                "DELETE FROM {} WHERE {} = $1",
                meta.table, meta.primary_key,
            );
            debug!(model = %meta.name, table = %meta.table, "ModelExt::delete (hard)");

            let mut query = sqlx::query(&sql);
            query = bind_field_value(query, &pk_value);

            let result = query
                .execute(db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

            if result.rows_affected() == 0 {
                return Err(VortexError::RecordNotFound {
                    model: meta.name.clone(),
                    id: field_value_to_record_id(&pk_value),
                });
            }
        }

        self.after_delete(ctx).await?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SecureModelExt implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl<M: Model> SecureModelExt for M {
    async fn find_secure(
        pool: &ConnectionPool,
        access: &dyn AccessControl,
        ctx: &Context,
        pk: impl Into<FieldValue> + Send,
    ) -> VortexResult<Option<Self>> {
        let meta = M::meta();

        // System context bypasses access checks
        if !ctx.is_system {
            access.check_read(ctx, &meta.name).await?;
        }

        // Find the record
        let record = M::find(pool, ctx, pk).await?;

        // Check record-level access
        if let Some(ref rec) = record {
            if !ctx.is_system {
                let values = rec.to_values();
                access.check_record_read(ctx, &meta.name, &values).await?;
            }
        }

        // Filter hidden fields
        if let Some(rec) = record {
            if !ctx.is_system {
                let accessible = access.get_accessible_fields(ctx, &meta.name).await?;
                let mut values = rec.to_values();
                values = accessible.filter_record(values);
                let filtered = M::from_values(values)?;
                Ok(Some(filtered))
            } else {
                Ok(Some(rec))
            }
        } else {
            Ok(None)
        }
    }

    async fn find_all_secure(
        pool: &ConnectionPool,
        access: &dyn AccessControl,
        ctx: &Context,
        filter: Filter,
    ) -> VortexResult<Vec<Self>> {
        let meta = M::meta();

        // System context bypasses access checks
        if !ctx.is_system {
            access.check_read(ctx, &meta.name).await?;
        }

        // Get domain filter from access control
        let combined_filter = if !ctx.is_system {
            let mut param_idx = 1000; // High offset to avoid collisions with user filter
            let domain = access
                .get_read_domain_sql(ctx, &meta.name, &mut param_idx)
                .await?;

            match domain {
                Some((domain_sql, domain_params)) => {
                    Filter::And(vec![
                        filter,
                        Filter::Raw(domain_sql, domain_params),
                    ])
                }
                None => filter,
            }
        } else {
            filter
        };

        // Execute query with combined filters
        let records = M::find_all(pool, ctx, combined_filter).await?;

        // Filter hidden fields if needed
        if !ctx.is_system {
            let accessible = access.get_accessible_fields(ctx, &meta.name).await?;
            if !accessible.hidden.is_empty() {
                let mut filtered = Vec::with_capacity(records.len());
                for rec in records {
                    let mut values = rec.to_values();
                    values = accessible.filter_record(values);
                    filtered.push(M::from_values(values)?);
                }
                return Ok(filtered);
            }
        }

        Ok(records)
    }

    async fn save_secure(
        &mut self,
        pool: &ConnectionPool,
        access: &dyn AccessControl,
        ctx: &Context,
    ) -> VortexResult<()> {
        let meta = M::meta();

        if !ctx.is_system {
            let pk_value = self.pk();
            let is_new = matches!(&pk_value, FieldValue::Null)
                || !record_exists(pool, meta, &pk_value).await?;

            if is_new {
                access.check_create(ctx, &meta.name).await?;
            } else {
                access.check_write(ctx, &meta.name).await?;
                // Check record-level write access
                let values = self.to_values();
                access.check_record_write(ctx, &meta.name, &values).await?;
            }

            // Verify field-level write permissions
            let accessible = access.get_accessible_fields(ctx, &meta.name).await?;
            let values = self.to_values();
            for (field_name, _) in &values {
                if !accessible.can_write(field_name) {
                    return Err(VortexError::AccessDenied {
                        action: format!("write field '{}'", field_name),
                        resource: meta.name.clone(),
                    });
                }
            }
        }

        self.save(pool, ctx).await
    }

    async fn delete_secure(
        self,
        pool: &ConnectionPool,
        access: &dyn AccessControl,
        ctx: &Context,
    ) -> VortexResult<()> {
        let meta = M::meta();

        if !ctx.is_system {
            access.check_delete(ctx, &meta.name).await?;

            // Check record-level delete access
            let values = self.to_values();
            access.check_record_write(ctx, &meta.name, &values).await?;
        }

        self.delete(pool, ctx).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch operations (browse pattern)
// ─────────────────────────────────────────────────────────────────────────────

/// Browse multiple records by IDs (Odoo's browse() pattern).
pub async fn browse<M: Model>(
    pool: &ConnectionPool,
    ctx: &Context,
    ids: Vec<FieldValue>,
) -> VortexResult<Vec<M>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let meta = M::meta();
    let dialect = pool.dialect();

    let mut param_idx = 1;
    let placeholders: Vec<String> = ids
        .iter()
        .map(|_| {
            let p = dialect.param_placeholder(param_idx);
            param_idx += 1;
            p
        })
        .collect();

    let mut conditions = vec![format!(
        "{} IN ({})",
        meta.primary_key,
        placeholders.join(", ")
    )];
    let mut params = ids.clone();

    // Multi-tenant filter
    if meta.multi_tenant {
        if let Some(company_id) = &ctx.company_id {
            conditions.push(format!("company_id = ${}", param_idx));
            params.push(FieldValue::Uuid(company_id.0));
            param_idx += 1;
        }
    }

    // Soft-delete filter
    if meta.soft_delete {
        conditions.push("deleted_at IS NULL".to_string());
    }

    let sql = format!(
        "SELECT {} FROM {} WHERE {}",
        meta.select_columns().join(", "),
        meta.table,
        conditions.join(" AND "),
    );

    let db = pool.pool();
    let mut query = sqlx::query(&sql);
    for p in &params {
        query = bind_field_value(query, p);
    }

    let rows = query
        .fetch_all(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let mut results = Vec::with_capacity(rows.len());
    for row in &rows {
        let values = row_to_values(row, meta);
        results.push(M::from_values(values)?);
    }

    Ok(results)
}

/// Count records matching a filter.
pub async fn count<M: Model>(
    pool: &ConnectionPool,
    ctx: &Context,
    filter: Filter,
) -> VortexResult<i64> {
    let meta = M::meta();
    let dialect = pool.dialect();

    let mut conditions = Vec::new();
    let mut params: Vec<FieldValue> = Vec::new();
    let mut param_idx = 1;

    // User filter
    let (filter_sql, filter_params) = filter.to_sql_with_dialect(dialect, &mut param_idx);
    if !filter_sql.is_empty() {
        conditions.push(filter_sql);
        params.extend(filter_params);
    }

    // Multi-tenant filter
    if meta.multi_tenant {
        if let Some(company_id) = &ctx.company_id {
            conditions.push(format!("company_id = ${}", param_idx));
            params.push(FieldValue::Uuid(company_id.0));
            param_idx += 1;
        }
    }

    // Soft-delete filter
    if meta.soft_delete {
        conditions.push("deleted_at IS NULL".to_string());
    }

    let mut sql = format!("SELECT COUNT(*) FROM {}", meta.table);
    if !conditions.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conditions.join(" AND "));
    }

    let db = pool.pool();
    let mut query = sqlx::query_scalar::<_, i64>(&sql);
    for p in &params {
        query = bind_field_value_scalar(query, p);
    }

    query
        .fetch_one(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Query execution (bridges Query → sqlx)
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a built Query and return model instances.
pub async fn execute_query<M: Model>(
    pool: &ConnectionPool,
    query: &crate::query::Query<M>,
) -> VortexResult<Vec<M>> {
    let meta = M::meta();
    let dialect = pool.dialect();

    let (sql, params) = query.to_sql_with_dialect(dialect);

    debug!(model = %meta.name, sql = %sql, "execute_query");

    let db = pool.pool();
    let mut sqlx_query = sqlx::query(&sql);
    for p in &params {
        sqlx_query = bind_field_value(sqlx_query, p);
    }

    let rows = sqlx_query
        .fetch_all(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let mut results = Vec::with_capacity(rows.len());
    for row in &rows {
        let values = row_to_values(row, meta);
        results.push(M::from_values(values)?);
    }

    Ok(results)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn field_value_to_record_id(value: &FieldValue) -> RecordId {
    match value {
        FieldValue::Uuid(u) => RecordId::Uuid(*u),
        FieldValue::Int(i) => RecordId::Int(*i),
        _ => RecordId::Int(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ModelMeta;

    // Test that build_insert_sql generates correct SQL
    #[test]
    fn test_build_insert_sql() {
        let mut meta = ModelMeta::new("Test", "test_table");
        meta.add_field(
            crate::field::FieldDef::new("id", FieldType::Uuid).primary_key(),
        );
        meta.add_field(
            crate::field::FieldDef::new("name", FieldType::Text).required(),
        );

        let mut values = HashMap::new();
        values.insert("id".to_string(), FieldValue::Uuid(Uuid::nil()));
        values.insert("name".to_string(), FieldValue::String("test".to_string()));

        let (sql, params) = build_insert_sql(&meta, &values);

        assert!(sql.starts_with("INSERT INTO test_table"));
        assert!(sql.contains("RETURNING *"));
        assert_eq!(params.len(), 2);
    }

    // Test that build_update_sql generates correct SQL
    #[test]
    fn test_build_update_sql() {
        let mut meta = ModelMeta::new("Test", "test_table");
        meta.add_field(
            crate::field::FieldDef::new("id", FieldType::Uuid).primary_key(),
        );
        meta.add_field(
            crate::field::FieldDef::new("name", FieldType::Text).required(),
        );

        let mut values = HashMap::new();
        values.insert("id".to_string(), FieldValue::Uuid(Uuid::nil()));
        values.insert("name".to_string(), FieldValue::String("updated".to_string()));

        let pk = FieldValue::Uuid(Uuid::nil());
        let (sql, params) = build_update_sql(&meta, &values, &pk);

        assert!(sql.starts_with("UPDATE test_table SET"));
        assert!(sql.contains("WHERE id = $"));
        // name param + pk param
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn test_make_cache_key() {
        let meta = ModelMeta::new("Asset", "eam_assets");
        let pk = FieldValue::Uuid(Uuid::nil());
        let key = make_cache_key(&meta, &pk, None);
        assert_eq!(key.model, "Asset");
        assert_eq!(key.pk, Uuid::nil().to_string());
        assert!(key.company_id.is_none());
    }

    #[test]
    fn test_make_cache_key_with_company() {
        let meta = ModelMeta::new("Asset", "eam_assets");
        let pk = FieldValue::Int(42);
        let company = CompanyId(Uuid::nil());
        let key = make_cache_key(&meta, &pk, Some(&company));
        assert_eq!(key.pk, "42");
        assert_eq!(key.company_id, Some(Uuid::nil().to_string()));
    }
}
