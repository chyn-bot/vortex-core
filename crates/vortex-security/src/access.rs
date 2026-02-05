//! Access control and record-level security rules

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vortex_common::{CompanyId, Context, UserId, VortexError, VortexResult};

/// Access control checker
pub struct AccessChecker {
    rules: Vec<RecordRule>,
}

impl AccessChecker {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a record rule
    pub fn add_rule(&mut self, rule: RecordRule) {
        self.rules.push(rule);
    }

    /// Check if access is allowed
    pub fn check_access(
        &self,
        ctx: &Context,
        model: &str,
        action: &str,
        record: Option<&HashMap<String, serde_json::Value>>,
    ) -> VortexResult<()> {
        // System context bypasses all checks
        if ctx.is_system {
            return Ok(());
        }

        // Find applicable rules
        let applicable_rules: Vec<_> = self.rules
            .iter()
            .filter(|r| r.applies_to(model, action))
            .collect();

        // If no rules, deny by default (secure default)
        if applicable_rules.is_empty() {
            return Err(VortexError::AccessDenied {
                action: action.to_string(),
                resource: model.to_string(),
            });
        }

        // Check each rule
        for rule in applicable_rules {
            if !rule.evaluate(ctx, record)? {
                return Err(VortexError::AccessDenied {
                    action: action.to_string(),
                    resource: model.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Get domain filter for queries
    pub fn get_domain_filter(&self, ctx: &Context, model: &str, action: &str) -> Option<String> {
        if ctx.is_system {
            return None;
        }

        let filters: Vec<String> = self.rules
            .iter()
            .filter(|r| r.applies_to(model, action))
            .filter_map(|r| r.get_domain_filter(ctx))
            .collect();

        if filters.is_empty() {
            None
        } else {
            Some(filters.join(" AND "))
        }
    }
}

impl Default for AccessChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Record-level security rule (domain-based filtering)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordRule {
    /// Rule name
    pub name: String,
    /// Model this rule applies to ("*" for all)
    pub model: String,
    /// Actions this rule applies to
    pub actions: Vec<String>,
    /// Domain expression (SQL-like)
    pub domain: String,
    /// Groups this rule applies to (empty = all)
    pub groups: Vec<String>,
    /// Whether this is a global rule
    pub is_global: bool,
    /// Priority (higher = evaluated first)
    pub priority: i32,
}

impl RecordRule {
    /// Create a new record rule
    pub fn new(name: impl Into<String>, model: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            model: model.into(),
            actions: vec!["read".to_string(), "write".to_string(), "create".to_string(), "unlink".to_string()],
            domain: domain.into(),
            groups: Vec::new(),
            is_global: false,
            priority: 0,
        }
    }

    /// Set actions
    pub fn with_actions(mut self, actions: Vec<&str>) -> Self {
        self.actions = actions.into_iter().map(String::from).collect();
        self
    }

    /// Set groups
    pub fn with_groups(mut self, groups: Vec<&str>) -> Self {
        self.groups = groups.into_iter().map(String::from).collect();
        self
    }

    /// Make global
    pub fn global(mut self) -> Self {
        self.is_global = true;
        self
    }

    /// Check if rule applies to model and action
    pub fn applies_to(&self, model: &str, action: &str) -> bool {
        (self.model == "*" || self.model == model)
            && (self.actions.contains(&"*".to_string()) || self.actions.contains(&action.to_string()))
    }

    /// Evaluate the rule for a specific record
    pub fn evaluate(
        &self,
        ctx: &Context,
        record: Option<&HashMap<String, serde_json::Value>>,
    ) -> VortexResult<bool> {
        // Check group membership if specified
        if !self.groups.is_empty() && !ctx.has_any_role(&self.groups.iter().map(|s| s.as_str()).collect::<Vec<_>>()) {
            // Rule doesn't apply to this user
            return Ok(true);
        }

        // Evaluate domain
        self.evaluate_domain(ctx, record)
    }

    /// Get SQL domain filter for queries
    pub fn get_domain_filter(&self, ctx: &Context) -> Option<String> {
        // Check group membership
        if !self.groups.is_empty() && !ctx.has_any_role(&self.groups.iter().map(|s| s.as_str()).collect::<Vec<_>>()) {
            return None;
        }

        // Replace variables in domain
        let mut domain = self.domain.clone();

        if let Some(user_id) = ctx.user_id {
            domain = domain.replace("current_user()", &format!("'{}'", user_id.0));
        }
        if let Some(company_id) = ctx.company_id {
            domain = domain.replace("current_company()", &format!("'{}'", company_id.0));
        }

        Some(domain)
    }

    /// Evaluate domain expression
    fn evaluate_domain(
        &self,
        ctx: &Context,
        record: Option<&HashMap<String, serde_json::Value>>,
    ) -> VortexResult<bool> {
        // Simple domain evaluation
        // In production, this would be a proper expression parser

        let domain = self.domain.to_lowercase();

        // Handle current_user() reference
        if domain.contains("user_id = current_user()") {
            if let Some(record) = record {
                if let Some(user_id) = ctx.user_id {
                    if let Some(record_user) = record.get("user_id") {
                        if let Some(record_user_str) = record_user.as_str() {
                            return Ok(record_user_str == user_id.0.to_string());
                        }
                    }
                }
            }
            return Ok(false);
        }

        // Handle current_company() reference
        if domain.contains("company_id = current_company()") {
            if let Some(record) = record {
                if let Some(company_id) = ctx.company_id {
                    if let Some(record_company) = record.get("company_id") {
                        if let Some(record_company_str) = record_company.as_str() {
                            return Ok(record_company_str == company_id.0.to_string());
                        }
                    }
                }
            }
            return Ok(false);
        }

        // Default: allow if domain is "(1=1)" or empty
        if domain.is_empty() || domain == "(1=1)" || domain == "true" {
            return Ok(true);
        }

        // Default: deny unknown domains
        Ok(false)
    }
}

/// Standard multi-tenant rule
pub fn multi_tenant_rule(model: &str) -> RecordRule {
    RecordRule::new(
        format!("{}_multi_tenant", model),
        model,
        "company_id = current_company()",
    )
    .global()
}

/// User owns record rule
pub fn user_owns_rule(model: &str) -> RecordRule {
    RecordRule::new(
        format!("{}_user_owns", model),
        model,
        "user_id = current_user()",
    )
}

/// Field-level access control
#[derive(Debug, Clone)]
pub struct FieldAccess {
    /// Fields that can be read
    pub readable: Vec<String>,
    /// Fields that can be written
    pub writable: Vec<String>,
    /// Fields that are always hidden
    pub hidden: Vec<String>,
}

impl FieldAccess {
    pub fn new() -> Self {
        Self {
            readable: Vec::new(),
            writable: Vec::new(),
            hidden: Vec::new(),
        }
    }

    /// All fields accessible
    pub fn all() -> Self {
        Self {
            readable: vec!["*".to_string()],
            writable: vec!["*".to_string()],
            hidden: Vec::new(),
        }
    }

    /// Read-only access
    pub fn readonly() -> Self {
        Self {
            readable: vec!["*".to_string()],
            writable: Vec::new(),
            hidden: Vec::new(),
        }
    }

    /// Check if field is readable
    pub fn can_read(&self, field: &str) -> bool {
        if self.hidden.contains(&field.to_string()) {
            return false;
        }
        self.readable.contains(&"*".to_string()) || self.readable.contains(&field.to_string())
    }

    /// Check if field is writable
    pub fn can_write(&self, field: &str) -> bool {
        if self.hidden.contains(&field.to_string()) {
            return false;
        }
        self.writable.contains(&"*".to_string()) || self.writable.contains(&field.to_string())
    }

    /// Filter a record to only include readable fields
    pub fn filter_readable(&self, record: &HashMap<String, serde_json::Value>) -> HashMap<String, serde_json::Value> {
        record
            .iter()
            .filter(|(k, _)| self.can_read(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Filter values to only include writable fields
    pub fn filter_writable(&self, values: &HashMap<String, serde_json::Value>) -> HashMap<String, serde_json::Value> {
        values
            .iter()
            .filter(|(k, _)| self.can_write(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl Default for FieldAccess {
    fn default() -> Self {
        Self::new()
    }
}
