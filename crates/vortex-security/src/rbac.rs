//! Role-Based Access Control (RBAC)
//!
//! Implements enterprise access-management requirements for regulated industries.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;
use vortex_common::{CompanyId, UserId, VortexResult, VortexError};

/// Permission definition
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission {
    /// Model/resource this permission applies to
    pub resource: String,
    /// Action (create, read, update, delete, or custom)
    pub action: String,
    /// Optional field restrictions
    pub fields: Option<Vec<String>>,
    /// Optional domain filter (record-level rule)
    pub domain: Option<String>,
}

impl Permission {
    /// Create a new permission
    pub fn new(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
            fields: None,
            domain: None,
        }
    }

    /// Add field restrictions
    pub fn with_fields(mut self, fields: Vec<String>) -> Self {
        self.fields = Some(fields);
        self
    }

    /// Add domain filter
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Check if this permission grants access to an action
    pub fn allows(&self, resource: &str, action: &str) -> bool {
        (self.resource == "*" || self.resource == resource)
            && (self.action == "*" || self.action == action)
    }

    /// Standard CRUD permissions
    pub fn create(resource: impl Into<String>) -> Self {
        Self::new(resource, "create")
    }

    pub fn read(resource: impl Into<String>) -> Self {
        Self::new(resource, "read")
    }

    pub fn update(resource: impl Into<String>) -> Self {
        Self::new(resource, "update")
    }

    pub fn delete(resource: impl Into<String>) -> Self {
        Self::new(resource, "delete")
    }

    pub fn all(resource: impl Into<String>) -> Self {
        Self::new(resource, "*")
    }
}

/// Role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique role ID
    pub id: Uuid,
    /// Role name (e.g., "admin", "operator", "viewer")
    pub name: String,
    /// Human-readable description
    pub description: Option<String>,
    /// Company this role belongs to (None for global roles)
    pub company_id: Option<CompanyId>,
    /// Permissions granted to this role
    pub permissions: HashSet<Permission>,
    /// Parent role for inheritance
    pub inherits_from: Option<Uuid>,
    /// Whether this is a system role (cannot be deleted)
    pub is_system: bool,
    /// CIP requirement this role helps satisfy
    pub cip_reference: Option<String>,
}

impl Role {
    /// Create a new role
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::now_v7(),
            name: name.into(),
            description: None,
            company_id: None,
            permissions: HashSet::new(),
            inherits_from: None,
            is_system: false,
            cip_reference: None,
        }
    }

    /// Create a company-specific role
    pub fn for_company(name: impl Into<String>, company_id: CompanyId) -> Self {
        Self {
            company_id: Some(company_id),
            ..Self::new(name)
        }
    }

    /// Add a permission
    pub fn grant(mut self, permission: Permission) -> Self {
        self.permissions.insert(permission);
        self
    }

    /// Remove a permission
    pub fn revoke(&mut self, permission: &Permission) {
        self.permissions.remove(permission);
    }

    /// Set parent role for inheritance
    pub fn inherits(mut self, parent_id: Uuid) -> Self {
        self.inherits_from = Some(parent_id);
        self
    }

    /// Mark as system role
    pub fn system(mut self) -> Self {
        self.is_system = true;
        self
    }

    /// Add CIP reference
    pub fn with_cip_reference(mut self, reference: impl Into<String>) -> Self {
        self.cip_reference = Some(reference.into());
        self
    }
}

/// Role manager for RBAC operations
pub struct RoleManager {
    /// Roles indexed by ID
    roles: RwLock<HashMap<Uuid, Role>>,
    /// Roles indexed by name (per company)
    roles_by_name: RwLock<HashMap<(Option<CompanyId>, String), Uuid>>,
    /// User role assignments
    user_roles: RwLock<HashMap<UserId, HashSet<Uuid>>>,
}

impl RoleManager {
    /// Create a new role manager
    pub fn new() -> Self {
        Self {
            roles: RwLock::new(HashMap::new()),
            roles_by_name: RwLock::new(HashMap::new()),
            user_roles: RwLock::new(HashMap::new()),
        }
    }

    /// Initialize with default system roles
    pub async fn init_system_roles(&self) {
        // Super Admin - full access (CIP-004 emergency access)
        let super_admin = Role::new("super_admin")
            .grant(Permission::new("*", "*"))
            .system()
            .with_cip_reference("CIP-004-7 R4.1");
        self.add_role(super_admin).await;

        // System Operator - operational access (CIP-004)
        let operator = Role::new("system_operator")
            .grant(Permission::read("*"))
            .grant(Permission::create("audit_log"))
            .system()
            .with_cip_reference("CIP-004-7 R4.2");
        self.add_role(operator).await;

        // Auditor - read-only access for compliance (CIP-004)
        let auditor = Role::new("auditor")
            .grant(Permission::read("*"))
            .grant(Permission::read("audit_log"))
            .system()
            .with_cip_reference("CIP-004-7 R4.3");
        self.add_role(auditor).await;

        // Viewer - basic read access
        let viewer = Role::new("viewer")
            .grant(Permission::read("*").with_domain("company_id = current_company()"))
            .system();
        self.add_role(viewer).await;

        info!("System roles initialized");
    }

    /// Add a role
    pub async fn add_role(&self, role: Role) -> Uuid {
        let id = role.id;
        let name = role.name.clone();
        let company_id = role.company_id;

        {
            let mut roles = self.roles.write().await;
            roles.insert(id, role);
        }

        {
            let mut by_name = self.roles_by_name.write().await;
            by_name.insert((company_id, name.clone()), id);
        }

        info!("Role added: {} ({})", name, id);
        id
    }

    /// Get a role by ID
    pub async fn get_role(&self, id: Uuid) -> Option<Role> {
        let roles = self.roles.read().await;
        roles.get(&id).cloned()
    }

    /// Get a role by name
    pub async fn get_role_by_name(&self, name: &str, company_id: Option<CompanyId>) -> Option<Role> {
        let id = {
            let by_name = self.roles_by_name.read().await;
            by_name.get(&(company_id, name.to_string())).copied()
        };
        match id {
            Some(id) => self.get_role(id).await,
            None => None,
        }
    }

    /// Assign a role to a user
    pub async fn assign_role(&self, user_id: UserId, role_id: Uuid) -> VortexResult<()> {
        // Verify role exists
        {
            let roles = self.roles.read().await;
            if !roles.contains_key(&role_id) {
                return Err(VortexError::ValidationFailed(format!(
                    "Role not found: {}",
                    role_id
                )));
            }
        }

        let mut user_roles = self.user_roles.write().await;
        user_roles.entry(user_id).or_default().insert(role_id);
        info!("Role {} assigned to user {}", role_id, user_id.0);
        Ok(())
    }

    /// Revoke a role from a user
    pub async fn revoke_role(&self, user_id: UserId, role_id: Uuid) {
        let mut user_roles = self.user_roles.write().await;
        if let Some(roles) = user_roles.get_mut(&user_id) {
            roles.remove(&role_id);
        }
        info!("Role {} revoked from user {}", role_id, user_id.0);
    }

    /// Get all roles for a user
    pub async fn get_user_roles(&self, user_id: UserId) -> Vec<Role> {
        let user_roles = self.user_roles.read().await;
        let role_ids = match user_roles.get(&user_id) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };
        drop(user_roles);

        let roles = self.roles.read().await;
        role_ids
            .iter()
            .filter_map(|id| roles.get(id).cloned())
            .collect()
    }

    /// Get all permissions for a user (including inherited)
    pub async fn get_user_permissions(&self, user_id: UserId) -> HashSet<Permission> {
        let user_roles = self.get_user_roles(user_id).await;
        let mut permissions = HashSet::new();

        for role in user_roles {
            permissions.extend(role.permissions.clone());

            // Handle inheritance
            if let Some(parent_id) = role.inherits_from {
                if let Some(parent) = self.get_role(parent_id).await {
                    permissions.extend(parent.permissions);
                }
            }
        }

        permissions
    }

    /// Check if a user has a specific permission
    pub async fn has_permission(
        &self,
        user_id: UserId,
        resource: &str,
        action: &str,
    ) -> bool {
        let permissions = self.get_user_permissions(user_id).await;
        permissions.iter().any(|p| p.allows(resource, action))
    }

    /// Get domain filters for a user's access to a resource
    pub async fn get_domain_filters(
        &self,
        user_id: UserId,
        resource: &str,
        action: &str,
    ) -> Vec<String> {
        let permissions = self.get_user_permissions(user_id).await;
        permissions
            .iter()
            .filter(|p| p.allows(resource, action))
            .filter_map(|p| p.domain.clone())
            .collect()
    }

    /// Delete a role (non-system roles only)
    pub async fn delete_role(&self, role_id: Uuid) -> VortexResult<()> {
        let mut roles = self.roles.write().await;

        if let Some(role) = roles.get(&role_id) {
            if role.is_system {
                return Err(VortexError::SecurityPolicyViolation(
                    "Cannot delete system role".to_string(),
                ));
            }
        }

        roles.remove(&role_id);
        info!("Role deleted: {}", role_id);
        Ok(())
    }
}

impl Default for RoleManager {
    fn default() -> Self {
        Self::new()
    }
}
