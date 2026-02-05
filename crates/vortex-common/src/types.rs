//! Core types used across Vortex

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for companies/tenants (multi-tenant isolation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CompanyId(pub Uuid);

impl CompanyId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for CompanyId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for users
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for modules
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ModuleId(pub String);

impl ModuleId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

/// Timestamp wrapper with audit context
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp(pub DateTime<Utc>);

impl Timestamp {
    pub fn now() -> Self {
        Self(Utc::now())
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

/// Standard audit fields present on all business records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFields {
    pub created_at: Timestamp,
    pub created_by: UserId,
    pub updated_at: Timestamp,
    pub updated_by: UserId,
    pub company_id: CompanyId,
}

impl AuditFields {
    pub fn new(user_id: UserId, company_id: CompanyId) -> Self {
        let now = Timestamp::now();
        Self {
            created_at: now,
            created_by: user_id,
            updated_at: now,
            updated_by: user_id,
            company_id,
        }
    }

    pub fn touch(&mut self, user_id: UserId) {
        self.updated_at = Timestamp::now();
        self.updated_by = user_id;
    }
}

/// Active/archived status for soft deletes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RecordStatus {
    #[default]
    Active,
    Archived,
    Deleted,
}

/// Field value types supported by the ORM
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Uuid(Uuid),
    Timestamp(DateTime<Utc>),
    Json(serde_json::Value),
    Binary(Vec<u8>),
    Array(Vec<FieldValue>),
}

impl FieldValue {
    pub fn is_null(&self) -> bool {
        matches!(self, FieldValue::Null)
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            FieldValue::Null => "null",
            FieldValue::Bool(_) => "bool",
            FieldValue::Int(_) => "int",
            FieldValue::Float(_) => "float",
            FieldValue::String(_) => "string",
            FieldValue::Uuid(_) => "uuid",
            FieldValue::Timestamp(_) => "timestamp",
            FieldValue::Json(_) => "json",
            FieldValue::Binary(_) => "binary",
            FieldValue::Array(_) => "array",
        }
    }
}

impl PartialEq for FieldValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (FieldValue::Null, FieldValue::Null) => true,
            (FieldValue::Bool(a), FieldValue::Bool(b)) => a == b,
            (FieldValue::Int(a), FieldValue::Int(b)) => a == b,
            (FieldValue::Float(a), FieldValue::Float(b)) => a == b,
            (FieldValue::String(a), FieldValue::String(b)) => a == b,
            (FieldValue::Uuid(a), FieldValue::Uuid(b)) => a == b,
            (FieldValue::Timestamp(a), FieldValue::Timestamp(b)) => a == b,
            (FieldValue::Binary(a), FieldValue::Binary(b)) => a == b,
            _ => false,
        }
    }
}

// From implementations for common types
impl From<bool> for FieldValue {
    fn from(v: bool) -> Self {
        FieldValue::Bool(v)
    }
}

impl From<i32> for FieldValue {
    fn from(v: i32) -> Self {
        FieldValue::Int(v as i64)
    }
}

impl From<i64> for FieldValue {
    fn from(v: i64) -> Self {
        FieldValue::Int(v)
    }
}

impl From<f32> for FieldValue {
    fn from(v: f32) -> Self {
        FieldValue::Float(v as f64)
    }
}

impl From<f64> for FieldValue {
    fn from(v: f64) -> Self {
        FieldValue::Float(v)
    }
}

impl From<String> for FieldValue {
    fn from(v: String) -> Self {
        FieldValue::String(v)
    }
}

impl From<&str> for FieldValue {
    fn from(v: &str) -> Self {
        FieldValue::String(v.to_string())
    }
}

impl From<Uuid> for FieldValue {
    fn from(v: Uuid) -> Self {
        FieldValue::Uuid(v)
    }
}

impl From<DateTime<Utc>> for FieldValue {
    fn from(v: DateTime<Utc>) -> Self {
        FieldValue::Timestamp(v)
    }
}

impl From<Vec<u8>> for FieldValue {
    fn from(v: Vec<u8>) -> Self {
        FieldValue::Binary(v)
    }
}

impl From<serde_json::Value> for FieldValue {
    fn from(v: serde_json::Value) -> Self {
        FieldValue::Json(v)
    }
}

impl<T: Into<FieldValue>> From<Option<T>> for FieldValue {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(val) => val.into(),
            None => FieldValue::Null,
        }
    }
}

/// Pagination parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    pub offset: u64,
    pub limit: u64,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 100,
        }
    }
}

impl Pagination {
    pub fn new(offset: u64, limit: u64) -> Self {
        Self { offset, limit }
    }

    pub fn page(page: u64, per_page: u64) -> Self {
        Self {
            offset: page.saturating_sub(1) * per_page,
            limit: per_page,
        }
    }
}
