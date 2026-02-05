//! Query builder with lazy evaluation

use crate::dialect::{NullsPosition, PostgresDialect, SqlDialect};
use crate::model::Model;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use vortex_common::{FieldValue, Pagination};

/// Query builder for constructing database queries
#[derive(Debug, Clone)]
pub struct QueryBuilder<M: Model> {
    filters: Vec<Filter>,
    order_by: Vec<OrderBy>,
    pagination: Option<Pagination>,
    select_fields: Option<Vec<String>>,
    joins: Vec<JoinClause>,
    group_by: Vec<String>,
    having: Option<Filter>,
    for_update: bool,
    _phantom: PhantomData<M>,
}

impl<M: Model> QueryBuilder<M> {
    /// Create a new query builder
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
            order_by: Vec::new(),
            pagination: None,
            select_fields: None,
            joins: Vec::new(),
            group_by: Vec::new(),
            having: None,
            for_update: false,
            _phantom: PhantomData,
        }
    }

    /// Add a filter condition
    pub fn filter(mut self, filter: Filter) -> Self {
        self.filters.push(filter);
        self
    }

    /// Add a WHERE clause using field = value
    pub fn where_eq(self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.filter(Filter::Eq(field.into(), value.into()))
    }

    /// Add a WHERE clause using field != value
    pub fn where_ne(self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.filter(Filter::Ne(field.into(), value.into()))
    }

    /// Add a WHERE clause using field > value
    pub fn where_gt(self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.filter(Filter::Gt(field.into(), value.into()))
    }

    /// Add a WHERE clause using field >= value
    pub fn where_gte(self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.filter(Filter::Gte(field.into(), value.into()))
    }

    /// Add a WHERE clause using field < value
    pub fn where_lt(self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.filter(Filter::Lt(field.into(), value.into()))
    }

    /// Add a WHERE clause using field <= value
    pub fn where_lte(self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.filter(Filter::Lte(field.into(), value.into()))
    }

    /// Add a WHERE clause using field LIKE pattern
    pub fn where_like(self, field: impl Into<String>, pattern: impl Into<String>) -> Self {
        self.filter(Filter::Like(field.into(), pattern.into()))
    }

    /// Add a WHERE clause using field ILIKE pattern (case insensitive)
    pub fn where_ilike(self, field: impl Into<String>, pattern: impl Into<String>) -> Self {
        self.filter(Filter::ILike(field.into(), pattern.into()))
    }

    /// Add a WHERE clause using field IN (values)
    pub fn where_in(self, field: impl Into<String>, values: Vec<FieldValue>) -> Self {
        self.filter(Filter::In(field.into(), values))
    }

    /// Add a WHERE clause using field NOT IN (values)
    pub fn where_not_in(self, field: impl Into<String>, values: Vec<FieldValue>) -> Self {
        self.filter(Filter::NotIn(field.into(), values))
    }

    /// Add a WHERE clause using field IS NULL
    pub fn where_null(self, field: impl Into<String>) -> Self {
        self.filter(Filter::IsNull(field.into()))
    }

    /// Add a WHERE clause using field IS NOT NULL
    pub fn where_not_null(self, field: impl Into<String>) -> Self {
        self.filter(Filter::IsNotNull(field.into()))
    }

    /// Add a WHERE clause using field BETWEEN low AND high
    pub fn where_between(
        self,
        field: impl Into<String>,
        low: impl Into<FieldValue>,
        high: impl Into<FieldValue>,
    ) -> Self {
        self.filter(Filter::Between(field.into(), low.into(), high.into()))
    }

    /// Add an ORDER BY clause
    pub fn order_by(mut self, field: impl Into<String>, direction: Direction) -> Self {
        self.order_by.push(OrderBy {
            field: field.into(),
            direction,
            nulls: NullsOrder::default(),
        });
        self
    }

    /// Add an ORDER BY ASC clause
    pub fn order_asc(self, field: impl Into<String>) -> Self {
        self.order_by(field, Direction::Asc)
    }

    /// Add an ORDER BY DESC clause
    pub fn order_desc(self, field: impl Into<String>) -> Self {
        self.order_by(field, Direction::Desc)
    }

    /// Add an ORDER BY clause with NULLS positioning
    pub fn order_by_nulls(
        mut self,
        field: impl Into<String>,
        direction: Direction,
        nulls: NullsOrder,
    ) -> Self {
        self.order_by.push(OrderBy {
            field: field.into(),
            direction,
            nulls,
        });
        self
    }

    /// Set pagination
    pub fn paginate(mut self, pagination: Pagination) -> Self {
        self.pagination = Some(pagination);
        self
    }

    /// Set limit
    pub fn limit(mut self, limit: u64) -> Self {
        self.pagination = Some(Pagination {
            offset: self.pagination.as_ref().map_or(0, |p| p.offset),
            limit,
        });
        self
    }

    /// Set offset
    pub fn offset(mut self, offset: u64) -> Self {
        self.pagination = Some(Pagination {
            offset,
            limit: self.pagination.as_ref().map_or(100, |p| p.limit),
        });
        self
    }

    /// Select specific fields only
    pub fn select(mut self, fields: Vec<String>) -> Self {
        self.select_fields = Some(fields);
        self
    }

    /// Add a JOIN clause
    pub fn join(mut self, join: JoinClause) -> Self {
        self.joins.push(join);
        self
    }

    /// Add a GROUP BY clause
    pub fn group_by(mut self, fields: Vec<String>) -> Self {
        self.group_by = fields;
        self
    }

    /// Add a HAVING clause
    pub fn having(mut self, filter: Filter) -> Self {
        self.having = Some(filter);
        self
    }

    /// Lock rows FOR UPDATE
    pub fn for_update(mut self) -> Self {
        self.for_update = true;
        self
    }

    /// Build the query into a Query struct
    pub fn build(self) -> Query<M> {
        Query {
            filters: self.filters,
            order_by: self.order_by,
            pagination: self.pagination,
            select_fields: self.select_fields,
            joins: self.joins,
            group_by: self.group_by,
            having: self.having,
            for_update: self.for_update,
            _phantom: PhantomData,
        }
    }
}

impl<M: Model> Default for QueryBuilder<M> {
    fn default() -> Self {
        Self::new()
    }
}

/// Built query ready for execution
#[derive(Debug, Clone)]
pub struct Query<M: Model> {
    pub filters: Vec<Filter>,
    pub order_by: Vec<OrderBy>,
    pub pagination: Option<Pagination>,
    pub select_fields: Option<Vec<String>>,
    pub joins: Vec<JoinClause>,
    pub group_by: Vec<String>,
    pub having: Option<Filter>,
    pub for_update: bool,
    _phantom: PhantomData<M>,
}

impl<M: Model> Query<M> {
    /// Generate SQL for this query using the specified dialect
    pub fn to_sql_with_dialect(&self, dialect: &dyn SqlDialect) -> (String, Vec<FieldValue>) {
        let meta = M::meta();
        let mut sql = String::new();
        let mut params: Vec<FieldValue> = Vec::new();
        let mut param_idx = 1;

        // SELECT clause
        let columns = self.select_fields.as_ref().map_or_else(
            || meta.select_columns().join(", "),
            |fields| fields.join(", "),
        );
        sql.push_str(&format!("SELECT {} FROM {}", columns, meta.table));

        // JOIN clauses
        for join in &self.joins {
            sql.push_str(&format!(
                " {} JOIN {} ON {}",
                join.join_type.as_str(),
                join.table,
                join.condition
            ));
        }

        // WHERE clause
        if !self.filters.is_empty() {
            sql.push_str(" WHERE ");
            let conditions: Vec<String> = self
                .filters
                .iter()
                .map(|f| {
                    let (cond, filter_params) = f.to_sql_with_dialect(dialect, &mut param_idx);
                    params.extend(filter_params);
                    cond
                })
                .collect();
            sql.push_str(&conditions.join(" AND "));
        }

        // GROUP BY clause
        if !self.group_by.is_empty() {
            sql.push_str(&format!(" GROUP BY {}", self.group_by.join(", ")));
        }

        // HAVING clause
        if let Some(having) = &self.having {
            let (cond, having_params) = having.to_sql_with_dialect(dialect, &mut param_idx);
            params.extend(having_params);
            sql.push_str(&format!(" HAVING {}", cond));
        }

        // ORDER BY clause
        if !self.order_by.is_empty() {
            sql.push_str(" ORDER BY ");
            let orders: Vec<String> = self
                .order_by
                .iter()
                .map(|o| {
                    let nulls_pos = match o.nulls {
                        NullsOrder::Default => NullsPosition::Default,
                        NullsOrder::First => NullsPosition::First,
                        NullsOrder::Last => NullsPosition::Last,
                    };
                    dialect.nulls_order(&o.field, o.direction.as_str(), nulls_pos)
                })
                .collect();
            sql.push_str(&orders.join(", "));
        }

        // LIMIT and OFFSET (dialect-specific)
        if let Some(pagination) = &self.pagination {
            sql.push(' ');
            sql.push_str(&dialect.pagination_sql(pagination.limit, pagination.offset));
        }

        // FOR UPDATE (dialect-specific)
        if self.for_update {
            sql.push(' ');
            sql.push_str(dialect.for_update_sql());
        }

        (sql, params)
    }

    /// Generate SQL for this query (backward compatible - uses PostgreSQL dialect)
    pub fn to_sql(&self) -> (String, Vec<FieldValue>) {
        self.to_sql_with_dialect(&PostgresDialect)
    }
}

/// Filter conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Filter {
    // Comparison operators
    Eq(String, FieldValue),
    Ne(String, FieldValue),
    Gt(String, FieldValue),
    Gte(String, FieldValue),
    Lt(String, FieldValue),
    Lte(String, FieldValue),

    // String operators
    Like(String, String),
    ILike(String, String),
    StartsWith(String, String),
    EndsWith(String, String),
    Contains(String, String),

    // Collection operators
    In(String, Vec<FieldValue>),
    NotIn(String, Vec<FieldValue>),
    Between(String, FieldValue, FieldValue),

    // Null checks
    IsNull(String),
    IsNotNull(String),

    // Logical operators
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),

    // Raw SQL (use with caution)
    Raw(String, Vec<FieldValue>),
}

impl Filter {
    /// Combine filters with AND
    pub fn and(filters: Vec<Filter>) -> Self {
        Filter::And(filters)
    }

    /// Combine filters with OR
    pub fn or(filters: Vec<Filter>) -> Self {
        Filter::Or(filters)
    }

    /// Negate a filter
    pub fn not(filter: Filter) -> Self {
        Filter::Not(Box::new(filter))
    }

    /// Convert filter to SQL using specified dialect
    pub fn to_sql_with_dialect(
        &self,
        dialect: &dyn SqlDialect,
        param_idx: &mut i32,
    ) -> (String, Vec<FieldValue>) {
        match self {
            Filter::Eq(field, value) => {
                let sql = format!("{} = {}", field, dialect.param_placeholder(*param_idx));
                *param_idx += 1;
                (sql, vec![value.clone()])
            }
            Filter::Ne(field, value) => {
                let sql = format!("{} != {}", field, dialect.param_placeholder(*param_idx));
                *param_idx += 1;
                (sql, vec![value.clone()])
            }
            Filter::Gt(field, value) => {
                let sql = format!("{} > {}", field, dialect.param_placeholder(*param_idx));
                *param_idx += 1;
                (sql, vec![value.clone()])
            }
            Filter::Gte(field, value) => {
                let sql = format!("{} >= {}", field, dialect.param_placeholder(*param_idx));
                *param_idx += 1;
                (sql, vec![value.clone()])
            }
            Filter::Lt(field, value) => {
                let sql = format!("{} < {}", field, dialect.param_placeholder(*param_idx));
                *param_idx += 1;
                (sql, vec![value.clone()])
            }
            Filter::Lte(field, value) => {
                let sql = format!("{} <= {}", field, dialect.param_placeholder(*param_idx));
                *param_idx += 1;
                (sql, vec![value.clone()])
            }
            Filter::Like(field, pattern) => {
                let sql = format!("{} LIKE {}", field, dialect.param_placeholder(*param_idx));
                *param_idx += 1;
                (sql, vec![FieldValue::String(pattern.clone())])
            }
            Filter::ILike(field, pattern) => {
                // Use dialect-specific ILIKE implementation
                let param = dialect.param_placeholder(*param_idx);
                let sql = dialect.ilike_expression(field, &param);
                *param_idx += 1;
                (sql, vec![FieldValue::String(pattern.clone())])
            }
            Filter::StartsWith(field, prefix) => {
                let sql = format!("{} LIKE {}", field, dialect.param_placeholder(*param_idx));
                *param_idx += 1;
                (sql, vec![FieldValue::String(format!("{}%", prefix))])
            }
            Filter::EndsWith(field, suffix) => {
                let sql = format!("{} LIKE {}", field, dialect.param_placeholder(*param_idx));
                *param_idx += 1;
                (sql, vec![FieldValue::String(format!("%{}", suffix))])
            }
            Filter::Contains(field, substr) => {
                let sql = format!("{} LIKE {}", field, dialect.param_placeholder(*param_idx));
                *param_idx += 1;
                (sql, vec![FieldValue::String(format!("%{}%", substr))])
            }
            Filter::In(field, values) => {
                let placeholders: Vec<String> = values
                    .iter()
                    .map(|_| {
                        let p = dialect.param_placeholder(*param_idx);
                        *param_idx += 1;
                        p
                    })
                    .collect();
                let sql = format!("{} IN ({})", field, placeholders.join(", "));
                (sql, values.clone())
            }
            Filter::NotIn(field, values) => {
                let placeholders: Vec<String> = values
                    .iter()
                    .map(|_| {
                        let p = dialect.param_placeholder(*param_idx);
                        *param_idx += 1;
                        p
                    })
                    .collect();
                let sql = format!("{} NOT IN ({})", field, placeholders.join(", "));
                (sql, values.clone())
            }
            Filter::Between(field, low, high) => {
                let sql = format!(
                    "{} BETWEEN {} AND {}",
                    field,
                    dialect.param_placeholder(*param_idx),
                    dialect.param_placeholder(*param_idx + 1)
                );
                *param_idx += 2;
                (sql, vec![low.clone(), high.clone()])
            }
            Filter::IsNull(field) => (format!("{} IS NULL", field), vec![]),
            Filter::IsNotNull(field) => (format!("{} IS NOT NULL", field), vec![]),
            Filter::And(filters) => {
                let mut all_params = Vec::new();
                let conditions: Vec<String> = filters
                    .iter()
                    .map(|f| {
                        let (cond, params) = f.to_sql_with_dialect(dialect, param_idx);
                        all_params.extend(params);
                        format!("({})", cond)
                    })
                    .collect();
                (conditions.join(" AND "), all_params)
            }
            Filter::Or(filters) => {
                let mut all_params = Vec::new();
                let conditions: Vec<String> = filters
                    .iter()
                    .map(|f| {
                        let (cond, params) = f.to_sql_with_dialect(dialect, param_idx);
                        all_params.extend(params);
                        format!("({})", cond)
                    })
                    .collect();
                (format!("({})", conditions.join(" OR ")), all_params)
            }
            Filter::Not(filter) => {
                let (cond, params) = filter.to_sql_with_dialect(dialect, param_idx);
                (format!("NOT ({})", cond), params)
            }
            Filter::Raw(sql, params) => (sql.clone(), params.clone()),
        }
    }

    /// Convert filter to SQL (backward compatible - uses PostgreSQL dialect)
    pub fn to_sql(&self, param_idx: &mut i32) -> (String, Vec<FieldValue>) {
        self.to_sql_with_dialect(&PostgresDialect, param_idx)
    }
}

/// Order by clause
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBy {
    pub field: String,
    pub direction: Direction,
    pub nulls: NullsOrder,
}

/// Sort direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Direction {
    #[default]
    Asc,
    Desc,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Asc => "ASC",
            Direction::Desc => "DESC",
        }
    }
}

/// Nulls ordering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NullsOrder {
    #[default]
    Default,
    First,
    Last,
}

impl NullsOrder {
    pub fn as_str(&self) -> &'static str {
        match self {
            NullsOrder::Default => "",
            NullsOrder::First => "NULLS FIRST",
            NullsOrder::Last => "NULLS LAST",
        }
    }
}

/// Join clause
#[derive(Debug, Clone)]
pub struct JoinClause {
    pub join_type: JoinType,
    pub table: String,
    pub condition: String,
}

/// Join types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JoinType {
    #[default]
    Inner,
    Left,
    Right,
    Full,
}

impl JoinType {
    pub fn as_str(&self) -> &'static str {
        match self {
            JoinType::Inner => "INNER",
            JoinType::Left => "LEFT",
            JoinType::Right => "RIGHT",
            JoinType::Full => "FULL",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Secure Query Builder with Access Control
// ─────────────────────────────────────────────────────────────────────────────

use vortex_common::Context;

impl<M: Model> QueryBuilder<M> {
    /// Apply access control to this query builder
    ///
    /// Returns a SecureQueryBuilder that will automatically apply
    /// access control filters when executed.
    pub fn with_access(self, ctx: Context) -> SecureQueryBuilder<M> {
        SecureQueryBuilder {
            inner: self,
            ctx,
        }
    }
}

/// A query builder that automatically applies access control
///
/// This wraps a regular QueryBuilder and adds access control checks
/// when the query is executed.
#[derive(Debug, Clone)]
pub struct SecureQueryBuilder<M: Model> {
    /// The underlying query builder
    pub inner: QueryBuilder<M>,
    /// The execution context for access control
    pub ctx: Context,
}

impl<M: Model> SecureQueryBuilder<M> {
    /// Create a new secure query builder
    pub fn new(ctx: Context) -> Self {
        Self {
            inner: QueryBuilder::new(),
            ctx,
        }
    }

    /// Add a filter condition
    pub fn filter(mut self, filter: Filter) -> Self {
        self.inner = self.inner.filter(filter);
        self
    }

    /// Add a WHERE clause using field = value
    pub fn where_eq(mut self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.inner = self.inner.where_eq(field, value);
        self
    }

    /// Add a WHERE clause using field != value
    pub fn where_ne(mut self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.inner = self.inner.where_ne(field, value);
        self
    }

    /// Add a WHERE clause using field > value
    pub fn where_gt(mut self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.inner = self.inner.where_gt(field, value);
        self
    }

    /// Add a WHERE clause using field >= value
    pub fn where_gte(mut self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.inner = self.inner.where_gte(field, value);
        self
    }

    /// Add a WHERE clause using field < value
    pub fn where_lt(mut self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.inner = self.inner.where_lt(field, value);
        self
    }

    /// Add a WHERE clause using field <= value
    pub fn where_lte(mut self, field: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.inner = self.inner.where_lte(field, value);
        self
    }

    /// Add a WHERE clause using field LIKE pattern
    pub fn where_like(mut self, field: impl Into<String>, pattern: impl Into<String>) -> Self {
        self.inner = self.inner.where_like(field, pattern);
        self
    }

    /// Add a WHERE clause using field ILIKE pattern (case insensitive)
    pub fn where_ilike(mut self, field: impl Into<String>, pattern: impl Into<String>) -> Self {
        self.inner = self.inner.where_ilike(field, pattern);
        self
    }

    /// Add a WHERE clause using field IN (values)
    pub fn where_in(mut self, field: impl Into<String>, values: Vec<FieldValue>) -> Self {
        self.inner = self.inner.where_in(field, values);
        self
    }

    /// Add a WHERE clause using field NOT IN (values)
    pub fn where_not_in(mut self, field: impl Into<String>, values: Vec<FieldValue>) -> Self {
        self.inner = self.inner.where_not_in(field, values);
        self
    }

    /// Add a WHERE clause using field IS NULL
    pub fn where_null(mut self, field: impl Into<String>) -> Self {
        self.inner = self.inner.where_null(field);
        self
    }

    /// Add a WHERE clause using field IS NOT NULL
    pub fn where_not_null(mut self, field: impl Into<String>) -> Self {
        self.inner = self.inner.where_not_null(field);
        self
    }

    /// Add a WHERE clause using field BETWEEN low AND high
    pub fn where_between(
        mut self,
        field: impl Into<String>,
        low: impl Into<FieldValue>,
        high: impl Into<FieldValue>,
    ) -> Self {
        self.inner = self.inner.where_between(field, low, high);
        self
    }

    /// Add an ORDER BY clause
    pub fn order_by(mut self, field: impl Into<String>, direction: Direction) -> Self {
        self.inner = self.inner.order_by(field, direction);
        self
    }

    /// Add an ORDER BY ASC clause
    pub fn order_asc(mut self, field: impl Into<String>) -> Self {
        self.inner = self.inner.order_asc(field);
        self
    }

    /// Add an ORDER BY DESC clause
    pub fn order_desc(mut self, field: impl Into<String>) -> Self {
        self.inner = self.inner.order_desc(field);
        self
    }

    /// Set pagination
    pub fn paginate(mut self, pagination: Pagination) -> Self {
        self.inner = self.inner.paginate(pagination);
        self
    }

    /// Set limit
    pub fn limit(mut self, limit: u64) -> Self {
        self.inner = self.inner.limit(limit);
        self
    }

    /// Set offset
    pub fn offset(mut self, offset: u64) -> Self {
        self.inner = self.inner.offset(offset);
        self
    }

    /// Select specific fields only
    pub fn select(mut self, fields: Vec<String>) -> Self {
        self.inner = self.inner.select(fields);
        self
    }

    /// Lock rows FOR UPDATE
    pub fn for_update(mut self) -> Self {
        self.inner = self.inner.for_update();
        self
    }

    /// Build into a SecureQuery
    pub fn build(self) -> SecureQuery<M> {
        SecureQuery {
            query: self.inner.build(),
            ctx: self.ctx,
        }
    }

    /// Get access to the inner query builder
    pub fn into_inner(self) -> QueryBuilder<M> {
        self.inner
    }

    /// Get access to the context
    pub fn context(&self) -> &Context {
        &self.ctx
    }
}

/// A built query with access control context
#[derive(Debug, Clone)]
pub struct SecureQuery<M: Model> {
    /// The underlying query
    pub query: Query<M>,
    /// The execution context for access control
    pub ctx: Context,
}

impl<M: Model> SecureQuery<M> {
    /// Get the model table name
    pub fn table_name(&self) -> &str {
        &M::meta().table
    }

    /// Get access to the underlying query
    pub fn inner(&self) -> &Query<M> {
        &self.query
    }

    /// Get access to the context
    pub fn context(&self) -> &Context {
        &self.ctx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "mssql")]
    use crate::dialect::MssqlDialect;

    // ─────────────────────────────────────────────────────────────────────────
    // Mock Model for testing
    // ─────────────────────────────────────────────────────────────────────────

    use crate::model::{ModelMeta, Model};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use vortex_common::{CompanyId, Context, VortexResult};

    /// A minimal mock model for testing QueryBuilder and Query
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestModel {
        id: i64,
        name: String,
    }

    // Static metadata for TestModel
    static TEST_MODEL_META: std::sync::OnceLock<ModelMeta> = std::sync::OnceLock::new();

    fn get_test_model_meta() -> &'static ModelMeta {
        TEST_MODEL_META.get_or_init(|| {
            ModelMeta::new("TestModel", "test_models")
        })
    }

    #[async_trait::async_trait]
    impl Model for TestModel {
        fn meta() -> &'static ModelMeta {
            get_test_model_meta()
        }

        fn pk(&self) -> FieldValue {
            FieldValue::Int(self.id)
        }

        fn company_id(&self) -> Option<CompanyId> {
            None
        }

        fn to_values(&self) -> HashMap<String, FieldValue> {
            let mut map = HashMap::new();
            map.insert("id".to_string(), FieldValue::Int(self.id));
            map.insert("name".to_string(), FieldValue::String(self.name.clone()));
            map
        }

        fn from_values(values: HashMap<String, FieldValue>) -> VortexResult<Self> {
            let id = match values.get("id") {
                Some(FieldValue::Int(v)) => *v,
                _ => 0,
            };
            let name = match values.get("name") {
                Some(FieldValue::String(v)) => v.clone(),
                _ => String::new(),
            };
            Ok(Self { id, name })
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Filter tests - PostgreSQL
    // ─────────────────────────────────────────────────────────────────────────

    mod postgres_filter_tests {
        use super::*;

        fn dialect() -> PostgresDialect {
            PostgresDialect
        }

        #[test]
        fn test_eq() {
            let filter = Filter::Eq("name".to_string(), FieldValue::String("test".to_string()));
            let (sql, params) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "name = $1");
            assert_eq!(params.len(), 1);
        }

        #[test]
        fn test_ne() {
            let filter = Filter::Ne("status".to_string(), FieldValue::String("deleted".to_string()));
            let (sql, _) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "status != $1");
        }

        #[test]
        fn test_gt_gte_lt_lte() {
            let d = dialect();

            let (sql, _) = Filter::Gt("age".to_string(), FieldValue::Int(18)).to_sql_with_dialect(&d, &mut 1);
            assert_eq!(sql, "age > $1");

            let (sql, _) = Filter::Gte("age".to_string(), FieldValue::Int(18)).to_sql_with_dialect(&d, &mut 1);
            assert_eq!(sql, "age >= $1");

            let (sql, _) = Filter::Lt("age".to_string(), FieldValue::Int(65)).to_sql_with_dialect(&d, &mut 1);
            assert_eq!(sql, "age < $1");

            let (sql, _) = Filter::Lte("age".to_string(), FieldValue::Int(65)).to_sql_with_dialect(&d, &mut 1);
            assert_eq!(sql, "age <= $1");
        }

        #[test]
        fn test_like() {
            let filter = Filter::Like("name".to_string(), "%john%".to_string());
            let (sql, params) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "name LIKE $1");
            assert_eq!(params[0], FieldValue::String("%john%".to_string()));
        }

        #[test]
        fn test_ilike() {
            let filter = Filter::ILike("email".to_string(), "%@example.com".to_string());
            let (sql, _) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "email ILIKE $1");
        }

        #[test]
        fn test_starts_with() {
            let filter = Filter::StartsWith("name".to_string(), "John".to_string());
            let (sql, params) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "name LIKE $1");
            assert_eq!(params[0], FieldValue::String("John%".to_string()));
        }

        #[test]
        fn test_ends_with() {
            let filter = Filter::EndsWith("email".to_string(), ".com".to_string());
            let (sql, params) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "email LIKE $1");
            assert_eq!(params[0], FieldValue::String("%.com".to_string()));
        }

        #[test]
        fn test_contains() {
            let filter = Filter::Contains("description".to_string(), "urgent".to_string());
            let (sql, params) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "description LIKE $1");
            assert_eq!(params[0], FieldValue::String("%urgent%".to_string()));
        }

        #[test]
        fn test_in() {
            let values = vec![
                FieldValue::Int(1),
                FieldValue::Int(2),
                FieldValue::Int(3),
            ];
            let filter = Filter::In("id".to_string(), values);
            let (sql, params) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "id IN ($1, $2, $3)");
            assert_eq!(params.len(), 3);
        }

        #[test]
        fn test_not_in() {
            let values = vec![
                FieldValue::String("deleted".to_string()),
                FieldValue::String("archived".to_string()),
            ];
            let filter = Filter::NotIn("status".to_string(), values);
            let (sql, _) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "status NOT IN ($1, $2)");
        }

        #[test]
        fn test_between() {
            let filter = Filter::Between(
                "created_at".to_string(),
                FieldValue::String("2024-01-01".to_string()),
                FieldValue::String("2024-12-31".to_string()),
            );
            let (sql, params) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "created_at BETWEEN $1 AND $2");
            assert_eq!(params.len(), 2);
        }

        #[test]
        fn test_is_null() {
            let filter = Filter::IsNull("deleted_at".to_string());
            let (sql, params) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "deleted_at IS NULL");
            assert!(params.is_empty());
        }

        #[test]
        fn test_is_not_null() {
            let filter = Filter::IsNotNull("email".to_string());
            let (sql, params) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "email IS NOT NULL");
            assert!(params.is_empty());
        }

        #[test]
        fn test_and() {
            let filter = Filter::And(vec![
                Filter::Eq("active".to_string(), FieldValue::Bool(true)),
                Filter::IsNotNull("email".to_string()),
            ]);
            let (sql, _) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "(active = $1) AND (email IS NOT NULL)");
        }

        #[test]
        fn test_or() {
            let filter = Filter::Or(vec![
                Filter::Eq("role".to_string(), FieldValue::String("admin".to_string())),
                Filter::Eq("role".to_string(), FieldValue::String("moderator".to_string())),
            ]);
            let (sql, _) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "((role = $1) OR (role = $2))");
        }

        #[test]
        fn test_not() {
            let filter = Filter::Not(Box::new(Filter::Eq(
                "deleted".to_string(),
                FieldValue::Bool(true),
            )));
            let (sql, _) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "NOT (deleted = $1)");
        }

        #[test]
        fn test_raw() {
            let filter = Filter::Raw(
                "custom_function(col) = $1".to_string(),
                vec![FieldValue::Int(42)],
            );
            let (sql, params) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "custom_function(col) = $1");
            assert_eq!(params.len(), 1);
        }

        #[test]
        fn test_param_index_increments() {
            let d = dialect();
            let mut idx = 1;

            let (sql1, _) = Filter::Eq("a".to_string(), FieldValue::Int(1)).to_sql_with_dialect(&d, &mut idx);
            assert_eq!(sql1, "a = $1");
            assert_eq!(idx, 2);

            let (sql2, _) = Filter::Eq("b".to_string(), FieldValue::Int(2)).to_sql_with_dialect(&d, &mut idx);
            assert_eq!(sql2, "b = $2");
            assert_eq!(idx, 3);
        }

        #[test]
        fn test_complex_nested_filter() {
            let filter = Filter::And(vec![
                Filter::Or(vec![
                    Filter::Eq("status".to_string(), FieldValue::String("active".to_string())),
                    Filter::Eq("status".to_string(), FieldValue::String("pending".to_string())),
                ]),
                Filter::Not(Box::new(Filter::IsNull("email".to_string()))),
                Filter::Gte("created_at".to_string(), FieldValue::String("2024-01-01".to_string())),
            ]);
            let (sql, params) = filter.to_sql_with_dialect(&dialect(), &mut 1);

            assert!(sql.contains("((status = $1) OR (status = $2))"));
            assert!(sql.contains("NOT (email IS NULL)"));
            assert!(sql.contains("created_at >= $3"));
            assert_eq!(params.len(), 3);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Filter tests - MSSQL
    // ─────────────────────────────────────────────────────────────────────────

    #[cfg(feature = "mssql")]
    mod mssql_filter_tests {
        use super::*;

        fn dialect() -> MssqlDialect {
            MssqlDialect
        }

        #[test]
        fn test_eq() {
            let filter = Filter::Eq("name".to_string(), FieldValue::String("test".to_string()));
            let (sql, _) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "name = @p1");
        }

        #[test]
        fn test_ilike_uses_lower() {
            let filter = Filter::ILike("name".to_string(), "%test%".to_string());
            let (sql, _) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "LOWER(name) LIKE LOWER(@p1)");
        }

        #[test]
        fn test_in() {
            let values = vec![FieldValue::Int(1), FieldValue::Int(2)];
            let filter = Filter::In("id".to_string(), values);
            let (sql, _) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "id IN (@p1, @p2)");
        }

        #[test]
        fn test_between() {
            let filter = Filter::Between(
                "value".to_string(),
                FieldValue::Int(10),
                FieldValue::Int(100),
            );
            let (sql, _) = filter.to_sql_with_dialect(&dialect(), &mut 1);
            assert_eq!(sql, "value BETWEEN @p1 AND @p2");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // QueryBuilder tests
    // ─────────────────────────────────────────────────────────────────────────

    mod query_builder_tests {
        use super::*;

        #[test]
        fn test_builder_default() {
            let builder: QueryBuilder<TestModel> = QueryBuilder::new();
            let query = builder.build();
            assert!(query.filters.is_empty());
            assert!(query.order_by.is_empty());
            assert!(query.pagination.is_none());
        }

        #[test]
        fn test_where_eq() {
            let query: Query<TestModel> = QueryBuilder::new()
                .where_eq("name", "John")
                .build();
            assert_eq!(query.filters.len(), 1);
            match &query.filters[0] {
                Filter::Eq(field, _) => assert_eq!(field, "name"),
                _ => panic!("Expected Eq filter"),
            }
        }

        #[test]
        fn test_chained_filters() {
            let query: Query<TestModel> = QueryBuilder::new()
                .where_eq("active", true)
                .where_ne("status", "deleted")
                .where_gt("age", 18i64)
                .build();
            assert_eq!(query.filters.len(), 3);
        }

        #[test]
        fn test_order_by() {
            let query: Query<TestModel> = QueryBuilder::new()
                .order_by("created_at", Direction::Desc)
                .order_asc("name")
                .build();

            assert_eq!(query.order_by.len(), 2);
            assert_eq!(query.order_by[0].field, "created_at");
            assert_eq!(query.order_by[0].direction, Direction::Desc);
            assert_eq!(query.order_by[1].field, "name");
            assert_eq!(query.order_by[1].direction, Direction::Asc);
        }

        #[test]
        fn test_order_by_with_nulls() {
            let query: Query<TestModel> = QueryBuilder::new()
                .order_by_nulls("email", Direction::Asc, NullsOrder::Last)
                .build();

            assert_eq!(query.order_by[0].nulls, NullsOrder::Last);
        }

        #[test]
        fn test_pagination() {
            let query: Query<TestModel> = QueryBuilder::new()
                .limit(25)
                .offset(50)
                .build();

            let pagination = query.pagination.unwrap();
            assert_eq!(pagination.limit, 25);
            assert_eq!(pagination.offset, 50);
        }

        #[test]
        fn test_select_fields() {
            let query: Query<TestModel> = QueryBuilder::new()
                .select(vec!["id".to_string(), "name".to_string()])
                .build();

            let fields = query.select_fields.unwrap();
            assert_eq!(fields, vec!["id", "name"]);
        }

        #[test]
        fn test_for_update() {
            let query: Query<TestModel> = QueryBuilder::new()
                .for_update()
                .build();

            assert!(query.for_update);
        }

        #[test]
        fn test_group_by_and_having() {
            let query: Query<TestModel> = QueryBuilder::new()
                .group_by(vec!["category".to_string()])
                .having(Filter::Gt("count".to_string(), FieldValue::Int(5)))
                .build();

            assert_eq!(query.group_by, vec!["category"]);
            assert!(query.having.is_some());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Direction and NullsOrder tests
    // ─────────────────────────────────────────────────────────────────────────

    mod direction_tests {
        use super::*;

        #[test]
        fn test_direction_as_str() {
            assert_eq!(Direction::Asc.as_str(), "ASC");
            assert_eq!(Direction::Desc.as_str(), "DESC");
        }

        #[test]
        fn test_direction_default() {
            assert_eq!(Direction::default(), Direction::Asc);
        }
    }

    mod nulls_order_tests {
        use super::*;

        #[test]
        fn test_nulls_order_as_str() {
            assert_eq!(NullsOrder::Default.as_str(), "");
            assert_eq!(NullsOrder::First.as_str(), "NULLS FIRST");
            assert_eq!(NullsOrder::Last.as_str(), "NULLS LAST");
        }

        #[test]
        fn test_nulls_order_default() {
            assert_eq!(NullsOrder::default(), NullsOrder::Default);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // JoinType tests
    // ─────────────────────────────────────────────────────────────────────────

    mod join_type_tests {
        use super::*;

        #[test]
        fn test_join_type_as_str() {
            assert_eq!(JoinType::Inner.as_str(), "INNER");
            assert_eq!(JoinType::Left.as_str(), "LEFT");
            assert_eq!(JoinType::Right.as_str(), "RIGHT");
            assert_eq!(JoinType::Full.as_str(), "FULL");
        }

        #[test]
        fn test_join_type_default() {
            assert_eq!(JoinType::default(), JoinType::Inner);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Filter helper method tests
    // ─────────────────────────────────────────────────────────────────────────

    mod filter_helper_tests {
        use super::*;

        #[test]
        fn test_filter_and_helper() {
            let filter = Filter::and(vec![
                Filter::Eq("a".to_string(), FieldValue::Int(1)),
                Filter::Eq("b".to_string(), FieldValue::Int(2)),
            ]);
            match filter {
                Filter::And(filters) => assert_eq!(filters.len(), 2),
                _ => panic!("Expected And filter"),
            }
        }

        #[test]
        fn test_filter_or_helper() {
            let filter = Filter::or(vec![
                Filter::Eq("x".to_string(), FieldValue::Int(1)),
                Filter::Eq("y".to_string(), FieldValue::Int(2)),
            ]);
            match filter {
                Filter::Or(filters) => assert_eq!(filters.len(), 2),
                _ => panic!("Expected Or filter"),
            }
        }

        #[test]
        fn test_filter_not_helper() {
            let filter = Filter::not(Filter::IsNull("col".to_string()));
            match filter {
                Filter::Not(_) => {}
                _ => panic!("Expected Not filter"),
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Backward compatibility tests
    // ─────────────────────────────────────────────────────────────────────────

    mod backward_compat_tests {
        use super::*;

        #[test]
        fn test_filter_to_sql_uses_postgres() {
            let filter = Filter::Eq("name".to_string(), FieldValue::String("test".to_string()));
            let (sql, _) = filter.to_sql(&mut 1);
            // Should use PostgreSQL placeholder
            assert_eq!(sql, "name = $1");
        }
    }
}
