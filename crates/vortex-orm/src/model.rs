//! Model trait and metadata definitions

use crate::field::FieldDef;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use vortex_common::{CompanyId, Context, FieldValue, VortexResult};

/// Metadata describing a model's structure
#[derive(Debug, Clone)]
pub struct ModelMeta {
    /// Model name (e.g., "User", "Product")
    pub name: String,
    /// Database table name
    pub table: String,
    /// Module this model belongs to
    pub module: String,
    /// Model description
    pub description: Option<String>,
    /// Field definitions indexed by name
    pub fields: HashMap<String, FieldDef>,
    /// Ordered list of field names
    pub field_order: Vec<String>,
    /// Primary key field name
    pub primary_key: String,
    /// Whether this model supports multi-tenancy
    pub multi_tenant: bool,
    /// Whether soft delete is enabled
    pub soft_delete: bool,
    /// Whether audit fields are included
    pub audited: bool,
    /// Indexes defined on the model
    pub indexes: Vec<IndexDef>,
    /// Constraints defined on the model
    pub constraints: Vec<ConstraintDef>,
    /// Parent model for inheritance (if any)
    pub inherits: Option<String>,
    /// Model-level access groups
    pub access_groups: Vec<String>,
}

impl ModelMeta {
    /// Create a new model metadata builder
    pub fn new(name: impl Into<String>, table: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            table: table.into(),
            module: "core".to_string(),
            description: None,
            fields: HashMap::new(),
            field_order: Vec::new(),
            primary_key: "id".to_string(),
            multi_tenant: true,
            soft_delete: true,
            audited: true,
            indexes: Vec::new(),
            constraints: Vec::new(),
            inherits: None,
            access_groups: Vec::new(),
        }
    }

    /// Add a field to the model
    pub fn add_field(&mut self, field: FieldDef) {
        self.field_order.push(field.name.clone());
        if field.primary_key {
            self.primary_key = field.name.clone();
        }
        self.fields.insert(field.name.clone(), field);
    }

    /// Get a field by name
    pub fn get_field(&self, name: &str) -> Option<&FieldDef> {
        self.fields.get(name)
    }

    /// Get all fields in order
    pub fn fields_ordered(&self) -> impl Iterator<Item = &FieldDef> {
        self.field_order.iter().filter_map(|n| self.fields.get(n))
    }

    /// Get column names for SELECT queries
    pub fn select_columns(&self) -> Vec<&str> {
        self.fields_ordered()
            .filter(|f| !matches!(f.field_type, crate::field::FieldType::Computed))
            .map(|f| f.column_name())
            .collect()
    }
}

/// Index definition
#[derive(Debug, Clone)]
pub struct IndexDef {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
    pub method: IndexMethod,
    pub where_clause: Option<String>,
}

/// Index method
#[derive(Debug, Clone, Default)]
pub enum IndexMethod {
    #[default]
    BTree,
    Hash,
    Gin,
    Gist,
    Brin,
}

/// Constraint definition
#[derive(Debug, Clone)]
pub struct ConstraintDef {
    pub name: String,
    pub constraint_type: ConstraintType,
}

/// Constraint types
#[derive(Debug, Clone)]
pub enum ConstraintType {
    Check { expression: String },
    Unique { columns: Vec<String> },
    ForeignKey {
        columns: Vec<String>,
        references_table: String,
        references_columns: Vec<String>,
        on_delete: crate::field::OnDelete,
    },
    Exclusion { expression: String },
}

/// Core trait that all Vortex models must implement
#[async_trait]
pub trait Model: Sized + Send + Sync + Serialize + DeserializeOwned + 'static {
    /// Get the model metadata
    fn meta() -> &'static ModelMeta;

    /// Get the primary key value
    fn pk(&self) -> FieldValue;

    /// Get the company ID for multi-tenant filtering
    fn company_id(&self) -> Option<CompanyId>;

    /// Convert the model to a field value map
    fn to_values(&self) -> HashMap<String, FieldValue>;

    /// Create a model instance from field values
    fn from_values(values: HashMap<String, FieldValue>) -> VortexResult<Self>;

    /// Validate the model before saving
    fn validate(&self, _ctx: &Context) -> VortexResult<()> {
        Ok(())
    }

    /// Hook called before insert
    async fn before_insert(&mut self, _ctx: &Context) -> VortexResult<()> {
        Ok(())
    }

    /// Hook called after insert
    async fn after_insert(&self, _ctx: &Context) -> VortexResult<()> {
        Ok(())
    }

    /// Hook called before update
    async fn before_update(&mut self, _ctx: &Context) -> VortexResult<()> {
        Ok(())
    }

    /// Hook called after update
    async fn after_update(&self, _ctx: &Context) -> VortexResult<()> {
        Ok(())
    }

    /// Hook called before delete
    async fn before_delete(&self, _ctx: &Context) -> VortexResult<()> {
        Ok(())
    }

    /// Hook called after delete
    async fn after_delete(&self, _ctx: &Context) -> VortexResult<()> {
        Ok(())
    }

    /// Compute derived fields
    fn compute_fields(&mut self, _ctx: &Context) -> VortexResult<()> {
        Ok(())
    }
}

/// Marker trait for models that support inheritance
pub trait InheritableModel: Model {
    /// The parent model type
    type Parent: Model;

    /// Get values from parent
    fn parent_values(&self) -> HashMap<String, FieldValue>;
}

/// Extension methods for Model types - requires a database connection
#[async_trait]
pub trait ModelExt: Model {
    /// Create a new query builder for this model
    fn query() -> crate::query::QueryBuilder<Self> {
        crate::query::QueryBuilder::new()
    }

    /// Find a record by primary key
    async fn find(
        pool: &crate::connection::ConnectionPool,
        ctx: &Context,
        pk: impl Into<FieldValue> + Send,
    ) -> VortexResult<Option<Self>>;

    /// Find all records matching a filter
    async fn find_all(
        pool: &crate::connection::ConnectionPool,
        ctx: &Context,
        filter: crate::query::Filter,
    ) -> VortexResult<Vec<Self>>;

    /// Save the record (insert or update)
    async fn save(
        &mut self,
        pool: &crate::connection::ConnectionPool,
        ctx: &Context,
    ) -> VortexResult<()>;

    /// Delete the record
    async fn delete(
        self,
        pool: &crate::connection::ConnectionPool,
        ctx: &Context,
    ) -> VortexResult<()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Secure Model Extension with Access Control
// ─────────────────────────────────────────────────────────────────────────────

use std::sync::Arc;

/// Access controller trait for dependency injection
///
/// This allows the ORM to work with any access controller implementation
/// without directly depending on vortex-security.
#[async_trait]
pub trait AccessControl: Send + Sync {
    /// Check if the user can read this model
    async fn check_read(&self, ctx: &Context, model: &str) -> VortexResult<()>;

    /// Check if the user can write this model
    async fn check_write(&self, ctx: &Context, model: &str) -> VortexResult<()>;

    /// Check if the user can create records in this model
    async fn check_create(&self, ctx: &Context, model: &str) -> VortexResult<()>;

    /// Check if the user can delete records in this model
    async fn check_delete(&self, ctx: &Context, model: &str) -> VortexResult<()>;

    /// Get the domain filter SQL for read operations
    async fn get_read_domain_sql(
        &self,
        ctx: &Context,
        model: &str,
        param_idx: &mut i32,
    ) -> VortexResult<Option<(String, Vec<FieldValue>)>>;

    /// Get accessible fields for the model
    async fn get_accessible_fields(
        &self,
        ctx: &Context,
        model: &str,
    ) -> VortexResult<AccessibleFields>;

    /// Check access for a specific record
    async fn check_record_read(
        &self,
        ctx: &Context,
        model: &str,
        record: &HashMap<String, FieldValue>,
    ) -> VortexResult<()>;

    /// Check access for writing a specific record
    async fn check_record_write(
        &self,
        ctx: &Context,
        model: &str,
        record: &HashMap<String, FieldValue>,
    ) -> VortexResult<()>;
}

/// Fields accessible to the current user
#[derive(Debug, Clone, Default)]
pub struct AccessibleFields {
    /// Fields that can be read (empty = all fields)
    pub readable: Vec<String>,
    /// Fields that can be written (empty = all fields)
    pub writable: Vec<String>,
    /// Fields that should be hidden from results
    pub hidden: Vec<String>,
}

impl AccessibleFields {
    /// Check if a field can be read
    pub fn can_read(&self, field: &str) -> bool {
        !self.hidden.contains(&field.to_string())
    }

    /// Check if a field can be written
    pub fn can_write(&self, field: &str) -> bool {
        if self.writable.is_empty() {
            !self.hidden.contains(&field.to_string())
        } else {
            self.writable.contains(&field.to_string())
        }
    }

    /// Filter a record to only include readable fields
    pub fn filter_record(&self, mut record: HashMap<String, FieldValue>) -> HashMap<String, FieldValue> {
        for field in &self.hidden {
            record.remove(field);
        }
        record
    }
}

/// Secure model extension with access control
///
/// This trait provides secure versions of database operations that
/// automatically check access control before executing.
#[async_trait]
pub trait SecureModelExt: Model {
    /// Create a secure query builder for this model
    fn secure_query(ctx: Context) -> crate::query::SecureQueryBuilder<Self> {
        crate::query::SecureQueryBuilder::new(ctx)
    }

    /// Find a record by primary key with access control
    async fn find_secure(
        pool: &crate::connection::ConnectionPool,
        access: &dyn AccessControl,
        ctx: &Context,
        pk: impl Into<FieldValue> + Send,
    ) -> VortexResult<Option<Self>>;

    /// Find all records matching a filter with access control
    async fn find_all_secure(
        pool: &crate::connection::ConnectionPool,
        access: &dyn AccessControl,
        ctx: &Context,
        filter: crate::query::Filter,
    ) -> VortexResult<Vec<Self>>;

    /// Save the record with access control (insert or update)
    async fn save_secure(
        &mut self,
        pool: &crate::connection::ConnectionPool,
        access: &dyn AccessControl,
        ctx: &Context,
    ) -> VortexResult<()>;

    /// Delete the record with access control
    async fn delete_secure(
        self,
        pool: &crate::connection::ConnectionPool,
        access: &dyn AccessControl,
        ctx: &Context,
    ) -> VortexResult<()>;
}

/// No-op access control that allows everything
///
/// Useful for testing or when access control is not needed.
pub struct NoAccessControl;

#[async_trait]
impl AccessControl for NoAccessControl {
    async fn check_read(&self, _ctx: &Context, _model: &str) -> VortexResult<()> {
        Ok(())
    }

    async fn check_write(&self, _ctx: &Context, _model: &str) -> VortexResult<()> {
        Ok(())
    }

    async fn check_create(&self, _ctx: &Context, _model: &str) -> VortexResult<()> {
        Ok(())
    }

    async fn check_delete(&self, _ctx: &Context, _model: &str) -> VortexResult<()> {
        Ok(())
    }

    async fn get_read_domain_sql(
        &self,
        _ctx: &Context,
        _model: &str,
        _param_idx: &mut i32,
    ) -> VortexResult<Option<(String, Vec<FieldValue>)>> {
        Ok(None)
    }

    async fn get_accessible_fields(
        &self,
        _ctx: &Context,
        _model: &str,
    ) -> VortexResult<AccessibleFields> {
        Ok(AccessibleFields::default())
    }

    async fn check_record_read(
        &self,
        _ctx: &Context,
        _model: &str,
        _record: &HashMap<String, FieldValue>,
    ) -> VortexResult<()> {
        Ok(())
    }

    async fn check_record_write(
        &self,
        _ctx: &Context,
        _model: &str,
        _record: &HashMap<String, FieldValue>,
    ) -> VortexResult<()> {
        Ok(())
    }
}
