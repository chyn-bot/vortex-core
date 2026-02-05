//! CSV Import/Export for Access Control Rules
//!
//! Supports Odoo-style CSV definitions for bulk configuration of access rules.
//! This enables easy deployment and version control of access configurations.
//!
//! # File Formats
//!
//! ## model_access.csv
//! ```csv
//! model,role,perm_read,perm_write,perm_create,perm_delete
//! users,admin,1,1,1,0
//! users,viewer,1,0,0,0
//! ```
//!
//! ## record_rules.csv
//! ```csv
//! name,model,role,domain,is_global,perm_read,perm_write,perm_create,perm_delete
//! multi_tenant_users,users,,company_id = current_company,1,1,1,1,1
//! ```

use crate::controller::{FieldAccessRule, ModelAccessRule, RecordRuleEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;
use vortex_common::{CompanyId, VortexError, VortexResult};

/// Model access CSV row
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAccessCsvRow {
    pub model: String,
    pub role: String,
    #[serde(deserialize_with = "deserialize_bool")]
    pub perm_read: bool,
    #[serde(deserialize_with = "deserialize_bool")]
    pub perm_write: bool,
    #[serde(deserialize_with = "deserialize_bool")]
    pub perm_create: bool,
    #[serde(deserialize_with = "deserialize_bool")]
    pub perm_delete: bool,
}

/// Record rule CSV row
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordRuleCsvRow {
    pub name: String,
    pub model: String,
    #[serde(default)]
    pub role: Option<String>,
    pub domain: String,
    #[serde(default, deserialize_with = "deserialize_bool_opt")]
    pub is_global: bool,
    #[serde(default = "default_true", deserialize_with = "deserialize_bool")]
    pub perm_read: bool,
    #[serde(default = "default_true", deserialize_with = "deserialize_bool")]
    pub perm_write: bool,
    #[serde(default = "default_true", deserialize_with = "deserialize_bool")]
    pub perm_create: bool,
    #[serde(default = "default_true", deserialize_with = "deserialize_bool")]
    pub perm_delete: bool,
    #[serde(default)]
    pub priority: Option<i32>,
}

/// Field access CSV row
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAccessCsvRow {
    pub model: String,
    pub field: String,
    pub role: String,
    #[serde(default = "default_true", deserialize_with = "deserialize_bool")]
    pub readable: bool,
    #[serde(default = "default_true", deserialize_with = "deserialize_bool")]
    pub writable: bool,
}

fn default_true() -> bool {
    true
}

/// Deserialize boolean from various formats (1/0, true/false, yes/no)
fn deserialize_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    match s.to_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "t" => Ok(true),
        "0" | "false" | "no" | "n" | "f" | "" => Ok(false),
        _ => Err(serde::de::Error::custom(format!(
            "Invalid boolean value: {}",
            s
        ))),
    }
}

fn deserialize_bool_opt<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        None => Ok(false),
        Some(s) => match s.to_lowercase().as_str() {
            "1" | "true" | "yes" | "y" | "t" => Ok(true),
            "0" | "false" | "no" | "n" | "f" | "" => Ok(false),
            _ => Err(serde::de::Error::custom(format!(
                "Invalid boolean value: {}",
                s
            ))),
        },
    }
}

/// Role resolver trait - maps role names to UUIDs
#[async_trait::async_trait]
pub trait RoleResolver: Send + Sync {
    /// Resolve a role name to its UUID
    async fn resolve_role(&self, name: &str) -> VortexResult<Option<Uuid>>;

    /// Create a role if it doesn't exist (optional)
    async fn ensure_role(&self, name: &str) -> VortexResult<Uuid>;
}

/// Simple in-memory role resolver
pub struct MemoryRoleResolver {
    roles: HashMap<String, Uuid>,
}

impl MemoryRoleResolver {
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
        }
    }

    pub fn with_roles(roles: HashMap<String, Uuid>) -> Self {
        Self { roles }
    }

    pub fn add_role(&mut self, name: impl Into<String>, id: Uuid) {
        self.roles.insert(name.into(), id);
    }
}

impl Default for MemoryRoleResolver {
    fn default() -> Self {
        let mut resolver = Self::new();
        // Add default system roles
        resolver.add_role(
            "super_admin",
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        );
        resolver.add_role(
            "admin",
            Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
        );
        resolver.add_role(
            "user",
            Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
        );
        resolver
    }
}

#[async_trait::async_trait]
impl RoleResolver for MemoryRoleResolver {
    async fn resolve_role(&self, name: &str) -> VortexResult<Option<Uuid>> {
        Ok(self.roles.get(name).copied())
    }

    async fn ensure_role(&self, name: &str) -> VortexResult<Uuid> {
        self.roles.get(name).copied().ok_or_else(|| {
            VortexError::ValidationFailed(format!("Role not found: {}", name))
        })
    }
}

/// CSV Loader for access control rules
pub struct CsvLoader<R: RoleResolver> {
    role_resolver: R,
}

impl<R: RoleResolver> CsvLoader<R> {
    pub fn new(role_resolver: R) -> Self {
        Self { role_resolver }
    }

    /// Load model access rules from CSV file
    pub async fn load_model_access_csv(
        &self,
        path: &Path,
    ) -> VortexResult<Vec<ModelAccessRule>> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            VortexError::ConfigurationError(format!("Failed to read CSV file: {}", e))
        })?;

        self.parse_model_access_csv(&content).await
    }

    /// Parse model access rules from CSV string
    pub async fn parse_model_access_csv(
        &self,
        content: &str,
    ) -> VortexResult<Vec<ModelAccessRule>> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .trim(csv::Trim::All)
            .flexible(true)
            .from_reader(content.as_bytes());

        let mut rules = Vec::new();

        for result in reader.deserialize() {
            let row: ModelAccessCsvRow = result.map_err(|e| {
                VortexError::ValidationFailed(format!("CSV parse error: {}", e))
            })?;

            let role_id = self.role_resolver.ensure_role(&row.role).await?;

            rules.push(ModelAccessRule {
                id: Uuid::now_v7(),
                model_name: row.model,
                role_id,
                perm_read: row.perm_read,
                perm_write: row.perm_write,
                perm_create: row.perm_create,
                perm_delete: row.perm_delete,
                company_id: None,
                active: true,
            });
        }

        Ok(rules)
    }

    /// Load record rules from CSV file
    pub async fn load_record_rules_csv(
        &self,
        path: &Path,
    ) -> VortexResult<Vec<RecordRuleEntry>> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            VortexError::ConfigurationError(format!("Failed to read CSV file: {}", e))
        })?;

        self.parse_record_rules_csv(&content).await
    }

    /// Parse record rules from CSV string
    pub async fn parse_record_rules_csv(
        &self,
        content: &str,
    ) -> VortexResult<Vec<RecordRuleEntry>> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .trim(csv::Trim::All)
            .flexible(true)
            .from_reader(content.as_bytes());

        let mut rules = Vec::new();

        for result in reader.deserialize() {
            let row: RecordRuleCsvRow = result.map_err(|e| {
                VortexError::ValidationFailed(format!("CSV parse error: {}", e))
            })?;

            let role_id = match &row.role {
                Some(name) if !name.is_empty() => {
                    Some(self.role_resolver.ensure_role(name).await?)
                }
                _ => None,
            };

            // Convert simple domain syntax to full domain expression
            let domain_expression = normalize_domain_expression(&row.domain);

            rules.push(RecordRuleEntry {
                id: Uuid::now_v7(),
                name: row.name,
                model_name: row.model,
                domain_expression,
                role_id,
                perm_read: row.perm_read,
                perm_write: row.perm_write,
                perm_create: row.perm_create,
                perm_delete: row.perm_delete,
                is_global: row.is_global,
                priority: row.priority.unwrap_or(0),
                active: true,
                company_id: None,
            });
        }

        Ok(rules)
    }

    /// Load field access rules from CSV file
    pub async fn load_field_access_csv(
        &self,
        path: &Path,
    ) -> VortexResult<Vec<FieldAccessRule>> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            VortexError::ConfigurationError(format!("Failed to read CSV file: {}", e))
        })?;

        self.parse_field_access_csv(&content).await
    }

    /// Parse field access rules from CSV string
    pub async fn parse_field_access_csv(
        &self,
        content: &str,
    ) -> VortexResult<Vec<FieldAccessRule>> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .trim(csv::Trim::All)
            .flexible(true)
            .from_reader(content.as_bytes());

        let mut rules = Vec::new();

        for result in reader.deserialize() {
            let row: FieldAccessCsvRow = result.map_err(|e| {
                VortexError::ValidationFailed(format!("CSV parse error: {}", e))
            })?;

            let role_id = self.role_resolver.ensure_role(&row.role).await?;

            rules.push(FieldAccessRule {
                id: Uuid::now_v7(),
                model_name: row.model,
                field_name: row.field,
                role_id,
                readable: row.readable,
                writable: row.writable,
                company_id: None,
                active: true,
            });
        }

        Ok(rules)
    }
}

/// Normalize a simple domain expression to full Odoo-style format
///
/// Converts:
/// - `company_id = current_company` -> `[("company_id", "=", current_company)]`
/// - `id = current_user` -> `[("id", "=", current_user)]`
fn normalize_domain_expression(input: &str) -> String {
    let input = input.trim();

    // Already in list format
    if input.starts_with('[') {
        return input.to_string();
    }

    // Empty domain
    if input.is_empty() {
        return "[]".to_string();
    }

    // Simple format: "field = value"
    // Parse and convert to list format
    let parts: Vec<&str> = input.splitn(3, |c| c == '=' || c == '!' || c == '<' || c == '>')
        .map(|s| s.trim())
        .collect();

    if parts.len() >= 2 {
        let field = parts[0].trim();

        // Find the operator
        let op_start = field.len();
        let remaining = &input[op_start..];
        let op = if remaining.starts_with("!=") || remaining.starts_with("<>") {
            "!="
        } else if remaining.starts_with("<=") {
            "<="
        } else if remaining.starts_with(">=") {
            ">="
        } else if remaining.starts_with('=') {
            "="
        } else if remaining.starts_with('<') {
            "<"
        } else if remaining.starts_with('>') {
            ">"
        } else {
            "="
        };

        // Get value after operator
        let op_len = op.len();
        let value_start = remaining.find(|c: char| c.is_alphanumeric() || c == '_' || c == '"' || c == '\'')
            .unwrap_or(op_len);
        let value = remaining[value_start..].trim();

        // Format value appropriately
        let formatted_value = if value == "current_user" || value == "current_company" || value == "null" || value == "true" || value == "false" {
            value.to_string()
        } else if value.starts_with('"') || value.starts_with('\'') {
            value.to_string()
        } else if value.parse::<i64>().is_ok() || value.parse::<f64>().is_ok() {
            value.to_string()
        } else {
            format!("\"{}\"", value)
        };

        return format!("[(\"{}\", \"{}\", {})]", field, op, formatted_value);
    }

    // Return as-is if we can't parse it
    input.to_string()
}

/// Export model access rules to CSV string
pub fn export_model_access_csv(rules: &[ModelAccessRule], role_names: &HashMap<Uuid, String>) -> String {
    let mut writer = csv::Writer::from_writer(vec![]);

    // Write header
    writer
        .write_record(["model", "role", "perm_read", "perm_write", "perm_create", "perm_delete"])
        .unwrap();

    for rule in rules {
        let role_name = role_names.get(&rule.role_id).cloned().unwrap_or_else(|| rule.role_id.to_string());
        let perm_read = if rule.perm_read { "1" } else { "0" };
        let perm_write = if rule.perm_write { "1" } else { "0" };
        let perm_create = if rule.perm_create { "1" } else { "0" };
        let perm_delete = if rule.perm_delete { "1" } else { "0" };

        writer
            .write_record([
                rule.model_name.as_str(),
                role_name.as_str(),
                perm_read,
                perm_write,
                perm_create,
                perm_delete,
            ])
            .unwrap();
    }

    String::from_utf8(writer.into_inner().unwrap()).unwrap()
}

/// Export record rules to CSV string
pub fn export_record_rules_csv(rules: &[RecordRuleEntry], role_names: &HashMap<Uuid, String>) -> String {
    let mut writer = csv::Writer::from_writer(vec![]);

    // Write header
    writer
        .write_record([
            "name", "model", "role", "domain", "is_global",
            "perm_read", "perm_write", "perm_create", "perm_delete", "priority"
        ])
        .unwrap();

    for rule in rules {
        let role_name = rule.role_id
            .and_then(|id| role_names.get(&id).cloned())
            .unwrap_or_default();
        let is_global = if rule.is_global { "1" } else { "0" };
        let perm_read = if rule.perm_read { "1" } else { "0" };
        let perm_write = if rule.perm_write { "1" } else { "0" };
        let perm_create = if rule.perm_create { "1" } else { "0" };
        let perm_delete = if rule.perm_delete { "1" } else { "0" };
        let priority = rule.priority.to_string();

        writer
            .write_record([
                rule.name.as_str(),
                rule.model_name.as_str(),
                role_name.as_str(),
                rule.domain_expression.as_str(),
                is_global,
                perm_read,
                perm_write,
                perm_create,
                perm_delete,
                priority.as_str(),
            ])
            .unwrap();
    }

    String::from_utf8(writer.into_inner().unwrap()).unwrap()
}

/// Export field access rules to CSV string
pub fn export_field_access_csv(rules: &[FieldAccessRule], role_names: &HashMap<Uuid, String>) -> String {
    let mut writer = csv::Writer::from_writer(vec![]);

    // Write header
    writer
        .write_record(["model", "field", "role", "readable", "writable"])
        .unwrap();

    for rule in rules {
        let role_name = role_names.get(&rule.role_id).cloned().unwrap_or_else(|| rule.role_id.to_string());
        let readable = if rule.readable { "1" } else { "0" };
        let writable = if rule.writable { "1" } else { "0" };

        writer
            .write_record([
                rule.model_name.as_str(),
                rule.field_name.as_str(),
                role_name.as_str(),
                readable,
                writable,
            ])
            .unwrap();
    }

    String::from_utf8(writer.into_inner().unwrap()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain_simple() {
        let result = normalize_domain_expression("company_id = current_company");
        assert_eq!(result, r#"[("company_id", "=", current_company)]"#);
    }

    #[test]
    fn test_normalize_domain_current_user() {
        let result = normalize_domain_expression("id = current_user");
        assert_eq!(result, r#"[("id", "=", current_user)]"#);
    }

    #[test]
    fn test_normalize_domain_already_list() {
        let input = r#"[("field", "=", "value")]"#;
        let result = normalize_domain_expression(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_normalize_domain_empty() {
        let result = normalize_domain_expression("");
        assert_eq!(result, "[]");
    }

    #[tokio::test]
    async fn test_parse_model_access_csv() {
        let resolver = MemoryRoleResolver::default();
        let loader = CsvLoader::new(resolver);

        let csv = r#"model,role,perm_read,perm_write,perm_create,perm_delete
users,super_admin,1,1,1,1
users,admin,1,1,1,0
users,user,1,0,0,0"#;

        let rules = loader.parse_model_access_csv(csv).await.unwrap();
        assert_eq!(rules.len(), 3);

        assert_eq!(rules[0].model_name, "users");
        assert!(rules[0].perm_read);
        assert!(rules[0].perm_write);
        assert!(rules[0].perm_create);
        assert!(rules[0].perm_delete);

        assert_eq!(rules[2].model_name, "users");
        assert!(rules[2].perm_read);
        assert!(!rules[2].perm_write);
    }

    #[tokio::test]
    async fn test_parse_record_rules_csv() {
        let resolver = MemoryRoleResolver::default();
        let loader = CsvLoader::new(resolver);

        let csv = r#"name,model,role,domain,is_global,perm_read,perm_write,perm_create,perm_delete
multi_tenant,users,,company_id = current_company,1,1,1,1,1
user_self,users,user,id = current_user,0,1,0,0,0"#;

        let rules = loader.parse_record_rules_csv(csv).await.unwrap();
        assert_eq!(rules.len(), 2);

        assert_eq!(rules[0].name, "multi_tenant");
        assert!(rules[0].is_global);
        assert!(rules[0].role_id.is_none());
        assert!(rules[0].domain_expression.contains("company_id"));

        assert_eq!(rules[1].name, "user_self");
        assert!(!rules[1].is_global);
        assert!(rules[1].role_id.is_some());
    }

    #[tokio::test]
    async fn test_parse_field_access_csv() {
        let resolver = MemoryRoleResolver::default();
        let loader = CsvLoader::new(resolver);

        let csv = r#"model,field,role,readable,writable
users,password_hash,user,0,0
users,email,user,1,0"#;

        let rules = loader.parse_field_access_csv(csv).await.unwrap();
        assert_eq!(rules.len(), 2);

        assert_eq!(rules[0].field_name, "password_hash");
        assert!(!rules[0].readable);
        assert!(!rules[0].writable);

        assert_eq!(rules[1].field_name, "email");
        assert!(rules[1].readable);
        assert!(!rules[1].writable);
    }

    #[test]
    fn test_export_model_access_csv() {
        let rules = vec![ModelAccessRule {
            id: Uuid::new_v4(),
            model_name: "users".to_string(),
            role_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            perm_read: true,
            perm_write: true,
            perm_create: false,
            perm_delete: false,
            company_id: None,
            active: true,
        }];

        let mut role_names = HashMap::new();
        role_names.insert(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            "admin".to_string(),
        );

        let csv = export_model_access_csv(&rules, &role_names);
        assert!(csv.contains("users"));
        assert!(csv.contains("admin"));
        assert!(csv.contains("1,1,0,0"));
    }
}
