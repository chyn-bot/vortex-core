//! Field definitions and types for the ORM

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_common::FieldValue;

/// Supported field types in the ORM
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    /// Auto-incrementing integer (BIGSERIAL)
    Serial,
    /// UUID v7 (time-ordered)
    Uuid,
    /// Boolean
    Boolean,
    /// 32-bit integer
    Integer,
    /// 64-bit integer
    BigInt,
    /// Single precision float
    Float,
    /// Double precision float
    Double,
    /// Fixed precision decimal
    Decimal { precision: u8, scale: u8 },
    /// Variable length string
    String { max_length: Option<u32> },
    /// Unlimited text
    Text,
    /// Date without time
    Date,
    /// Time without date
    Time,
    /// Timestamp with timezone
    Timestamp,
    /// JSON/JSONB data
    Json,
    /// Binary data
    Binary,
    /// Array of another type
    Array(Box<FieldType>),
    /// Reference to another model (foreign key)
    Reference { model: String, on_delete: OnDelete },
    /// Enum type
    Enum { name: String, values: Vec<String> },
    /// Computed field (not stored)
    Computed,
}

/// Foreign key ON DELETE behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OnDelete {
    #[default]
    Restrict,
    Cascade,
    SetNull,
    SetDefault,
    NoAction,
}

/// Field definition with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    /// Field name in the model
    pub name: String,
    /// Database column name (if different)
    pub column: Option<String>,
    /// Field type
    pub field_type: FieldType,
    /// Whether the field is required (NOT NULL)
    pub required: bool,
    /// Whether this is a primary key
    pub primary_key: bool,
    /// Whether this field should be unique
    pub unique: bool,
    /// Whether this field should be indexed
    pub indexed: bool,
    /// Default value expression
    pub default: Option<DefaultValue>,
    /// Field description for documentation
    pub description: Option<String>,
    /// Whether this field is readonly after creation
    pub readonly: bool,
    /// Whether to include in audit log on change
    pub audit: bool,
    /// Dependencies for computed fields
    pub depends_on: Vec<String>,
    /// Field-level encryption for sensitive data
    pub encrypted: bool,
    /// Field-level access groups
    pub access_groups: Vec<String>,
}

impl FieldDef {
    /// Create a new field definition
    pub fn new(name: impl Into<String>, field_type: FieldType) -> Self {
        Self {
            name: name.into(),
            column: None,
            field_type,
            required: false,
            primary_key: false,
            unique: false,
            indexed: false,
            default: None,
            description: None,
            readonly: false,
            audit: true,
            depends_on: Vec::new(),
            encrypted: false,
            access_groups: Vec::new(),
        }
    }

    /// Get the database column name
    pub fn column_name(&self) -> &str {
        self.column.as_deref().unwrap_or(&self.name)
    }

    /// Builder methods
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn primary_key(mut self) -> Self {
        self.primary_key = true;
        self.required = true;
        self
    }

    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }

    pub fn indexed(mut self) -> Self {
        self.indexed = true;
        self
    }

    pub fn with_default(mut self, default: DefaultValue) -> Self {
        self.default = Some(default);
        self
    }

    pub fn readonly(mut self) -> Self {
        self.readonly = true;
        self
    }

    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    pub fn with_access_groups(mut self, groups: Vec<String>) -> Self {
        self.access_groups = groups;
        self
    }

    pub fn computed(mut self, depends_on: Vec<String>) -> Self {
        self.field_type = FieldType::Computed;
        self.depends_on = depends_on;
        self
    }
}

/// Default value for a field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DefaultValue {
    /// Literal value
    Value(FieldValue),
    /// SQL expression (e.g., "NOW()", "gen_random_uuid()")
    Expression(String),
    /// Computed at runtime by Vortex
    Function(String),
}

/// Trait for types that can be used as ORM fields
pub trait Field: Sized + Send + Sync {
    /// The corresponding FieldType
    fn field_type() -> FieldType;

    /// Convert from FieldValue
    fn from_field_value(value: FieldValue) -> vortex_common::VortexResult<Self>;

    /// Convert to FieldValue
    fn to_field_value(&self) -> FieldValue;
}

// ─────────────────────────────────────────────────────────────────────────────
// Field implementations for common types
// ─────────────────────────────────────────────────────────────────────────────

impl Field for bool {
    fn field_type() -> FieldType {
        FieldType::Boolean
    }

    fn from_field_value(value: FieldValue) -> vortex_common::VortexResult<Self> {
        match value {
            FieldValue::Bool(b) => Ok(b),
            _ => Err(vortex_common::VortexError::InvalidFieldValue {
                field: "bool".to_string(),
                reason: format!("expected bool, got {}", value.type_name()),
            }),
        }
    }

    fn to_field_value(&self) -> FieldValue {
        FieldValue::Bool(*self)
    }
}

impl Field for i32 {
    fn field_type() -> FieldType {
        FieldType::Integer
    }

    fn from_field_value(value: FieldValue) -> vortex_common::VortexResult<Self> {
        match value {
            FieldValue::Int(i) => i.try_into().map_err(|_| {
                vortex_common::VortexError::InvalidFieldValue {
                    field: "i32".to_string(),
                    reason: "value out of range".to_string(),
                }
            }),
            _ => Err(vortex_common::VortexError::InvalidFieldValue {
                field: "i32".to_string(),
                reason: format!("expected int, got {}", value.type_name()),
            }),
        }
    }

    fn to_field_value(&self) -> FieldValue {
        FieldValue::Int(*self as i64)
    }
}

impl Field for i64 {
    fn field_type() -> FieldType {
        FieldType::BigInt
    }

    fn from_field_value(value: FieldValue) -> vortex_common::VortexResult<Self> {
        match value {
            FieldValue::Int(i) => Ok(i),
            _ => Err(vortex_common::VortexError::InvalidFieldValue {
                field: "i64".to_string(),
                reason: format!("expected int, got {}", value.type_name()),
            }),
        }
    }

    fn to_field_value(&self) -> FieldValue {
        FieldValue::Int(*self)
    }
}

impl Field for f64 {
    fn field_type() -> FieldType {
        FieldType::Double
    }

    fn from_field_value(value: FieldValue) -> vortex_common::VortexResult<Self> {
        match value {
            FieldValue::Float(f) => Ok(f),
            FieldValue::Int(i) => Ok(i as f64),
            _ => Err(vortex_common::VortexError::InvalidFieldValue {
                field: "f64".to_string(),
                reason: format!("expected float, got {}", value.type_name()),
            }),
        }
    }

    fn to_field_value(&self) -> FieldValue {
        FieldValue::Float(*self)
    }
}

impl Field for String {
    fn field_type() -> FieldType {
        FieldType::Text
    }

    fn from_field_value(value: FieldValue) -> vortex_common::VortexResult<Self> {
        match value {
            FieldValue::String(s) => Ok(s),
            _ => Err(vortex_common::VortexError::InvalidFieldValue {
                field: "String".to_string(),
                reason: format!("expected string, got {}", value.type_name()),
            }),
        }
    }

    fn to_field_value(&self) -> FieldValue {
        FieldValue::String(self.clone())
    }
}

impl Field for Uuid {
    fn field_type() -> FieldType {
        FieldType::Uuid
    }

    fn from_field_value(value: FieldValue) -> vortex_common::VortexResult<Self> {
        match value {
            FieldValue::Uuid(u) => Ok(u),
            FieldValue::String(s) => Uuid::parse_str(&s).map_err(|_| {
                vortex_common::VortexError::InvalidFieldValue {
                    field: "Uuid".to_string(),
                    reason: "invalid UUID string".to_string(),
                }
            }),
            _ => Err(vortex_common::VortexError::InvalidFieldValue {
                field: "Uuid".to_string(),
                reason: format!("expected uuid, got {}", value.type_name()),
            }),
        }
    }

    fn to_field_value(&self) -> FieldValue {
        FieldValue::Uuid(*self)
    }
}

impl Field for DateTime<Utc> {
    fn field_type() -> FieldType {
        FieldType::Timestamp
    }

    fn from_field_value(value: FieldValue) -> vortex_common::VortexResult<Self> {
        match value {
            FieldValue::Timestamp(t) => Ok(t),
            _ => Err(vortex_common::VortexError::InvalidFieldValue {
                field: "DateTime".to_string(),
                reason: format!("expected timestamp, got {}", value.type_name()),
            }),
        }
    }

    fn to_field_value(&self) -> FieldValue {
        FieldValue::Timestamp(*self)
    }
}

impl Field for serde_json::Value {
    fn field_type() -> FieldType {
        FieldType::Json
    }

    fn from_field_value(value: FieldValue) -> vortex_common::VortexResult<Self> {
        match value {
            FieldValue::Json(j) => Ok(j),
            _ => Err(vortex_common::VortexError::InvalidFieldValue {
                field: "Json".to_string(),
                reason: format!("expected json, got {}", value.type_name()),
            }),
        }
    }

    fn to_field_value(&self) -> FieldValue {
        FieldValue::Json(self.clone())
    }
}

impl<T: Field> Field for Option<T> {
    fn field_type() -> FieldType {
        T::field_type()
    }

    fn from_field_value(value: FieldValue) -> vortex_common::VortexResult<Self> {
        match value {
            FieldValue::Null => Ok(None),
            other => T::from_field_value(other).map(Some),
        }
    }

    fn to_field_value(&self) -> FieldValue {
        match self {
            Some(v) => v.to_field_value(),
            None => FieldValue::Null,
        }
    }
}

impl<T: Field> Field for Vec<T> {
    fn field_type() -> FieldType {
        FieldType::Array(Box::new(T::field_type()))
    }

    fn from_field_value(value: FieldValue) -> vortex_common::VortexResult<Self> {
        match value {
            FieldValue::Array(arr) => arr.into_iter().map(T::from_field_value).collect(),
            _ => Err(vortex_common::VortexError::InvalidFieldValue {
                field: "Vec".to_string(),
                reason: format!("expected array, got {}", value.type_name()),
            }),
        }
    }

    fn to_field_value(&self) -> FieldValue {
        FieldValue::Array(self.iter().map(|v| v.to_field_value()).collect())
    }
}
