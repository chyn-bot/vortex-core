//! Model inheritance system

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vortex_common::VortexResult;

/// Types of model inheritance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InheritanceType {
    /// Classical inheritance - child extends parent, stored in same table
    /// Similar to Odoo's _inherit without _name
    Extension,

    /// Prototype inheritance - child copies parent's fields
    /// Similar to Odoo's _inherit with _name
    Prototype,

    /// Delegation - child has reference to parent
    /// Similar to Odoo's _inherits
    Delegation,
}

/// Model extension definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelExtension {
    /// Extension name/identifier
    pub name: String,
    /// Module providing this extension
    pub module: String,
    /// Target model being extended
    pub target_model: String,
    /// Type of inheritance
    pub inheritance_type: InheritanceType,
    /// New fields to add
    pub new_fields: Vec<FieldExtension>,
    /// Fields to modify
    pub modified_fields: Vec<FieldModification>,
    /// New methods/overrides
    pub methods: Vec<MethodOverride>,
    /// Constraints to add
    pub constraints: Vec<ConstraintExtension>,
}

impl ModelExtension {
    /// Create a new model extension
    pub fn new(
        name: impl Into<String>,
        module: impl Into<String>,
        target: impl Into<String>,
        inheritance_type: InheritanceType,
    ) -> Self {
        Self {
            name: name.into(),
            module: module.into(),
            target_model: target.into(),
            inheritance_type,
            new_fields: Vec::new(),
            modified_fields: Vec::new(),
            methods: Vec::new(),
            constraints: Vec::new(),
        }
    }

    /// Add a new field
    pub fn add_field(mut self, field: FieldExtension) -> Self {
        self.new_fields.push(field);
        self
    }

    /// Modify an existing field
    pub fn modify_field(mut self, modification: FieldModification) -> Self {
        self.modified_fields.push(modification);
        self
    }

    /// Add a method override
    pub fn add_method(mut self, method: MethodOverride) -> Self {
        self.methods.push(method);
        self
    }

    /// Add a constraint
    pub fn add_constraint(mut self, constraint: ConstraintExtension) -> Self {
        self.constraints.push(constraint);
        self
    }
}

/// Field extension (adding new field to existing model)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldExtension {
    /// Field name
    pub name: String,
    /// Field type (serialized)
    pub field_type: String,
    /// Whether field is required
    pub required: bool,
    /// Default value
    pub default: Option<String>,
    /// Field description
    pub description: Option<String>,
}

impl FieldExtension {
    pub fn new(name: impl Into<String>, field_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            field_type: field_type.into(),
            required: false,
            default: None,
            description: None,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn with_default(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self
    }
}

/// Field modification (changing existing field)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldModification {
    /// Target field name
    pub field_name: String,
    /// New required state
    pub required: Option<bool>,
    /// New default value
    pub default: Option<String>,
    /// New readonly state
    pub readonly: Option<bool>,
    /// New string/label
    pub label: Option<String>,
    /// Make invisible
    pub invisible: Option<bool>,
}

impl FieldModification {
    pub fn new(field_name: impl Into<String>) -> Self {
        Self {
            field_name: field_name.into(),
            required: None,
            default: None,
            readonly: None,
            label: None,
            invisible: None,
        }
    }

    pub fn set_required(mut self, required: bool) -> Self {
        self.required = Some(required);
        self
    }

    pub fn set_readonly(mut self, readonly: bool) -> Self {
        self.readonly = Some(readonly);
        self
    }

    pub fn set_default(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self
    }
}

/// Method override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodOverride {
    /// Method name
    pub method_name: String,
    /// Override type
    pub override_type: OverrideType,
    /// Module providing the override
    pub module: String,
}

/// Type of method override
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverrideType {
    /// Replace the method entirely
    Replace,
    /// Call before the original
    Before,
    /// Call after the original
    After,
    /// Wrap the original (call super within)
    Wrap,
}

/// Constraint extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintExtension {
    /// Constraint name
    pub name: String,
    /// Constraint type
    pub constraint_type: ExtendedConstraintType,
}

/// Extended constraint types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtendedConstraintType {
    /// SQL check constraint
    Check { expression: String },
    /// Unique constraint
    Unique { fields: Vec<String> },
    /// Python/Rust constraint (validation function)
    Validation { message: String },
}

/// Extension registry
pub struct ExtensionRegistry {
    extensions: HashMap<String, Vec<ModelExtension>>,
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self {
            extensions: HashMap::new(),
        }
    }

    /// Register an extension
    pub fn register(&mut self, extension: ModelExtension) {
        self.extensions
            .entry(extension.target_model.clone())
            .or_default()
            .push(extension);
    }

    /// Get all extensions for a model
    pub fn get_extensions(&self, model: &str) -> Vec<&ModelExtension> {
        self.extensions
            .get(model)
            .map(|exts| exts.iter().collect())
            .unwrap_or_default()
    }

    /// Check if a model has extensions
    pub fn has_extensions(&self, model: &str) -> bool {
        self.extensions
            .get(model)
            .map(|exts| !exts.is_empty())
            .unwrap_or(false)
    }

    /// Remove extensions from a module
    pub fn unregister_module(&mut self, module: &str) {
        for extensions in self.extensions.values_mut() {
            extensions.retain(|e| e.module != module);
        }
    }
}

impl Default for ExtensionRegistry {
    fn default() -> Self {
        Self::new()
    }
}
