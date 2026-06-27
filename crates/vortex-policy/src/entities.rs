//! Mapping from Vortex domain types to Cedar [`Entity`] / [`EntityUid`].
//!
//! Cedar needs every subject, action, and resource referenced by a policy
//! to exist as an `Entity` in the request's entity set. This module is
//! the single place where Vortex types are projected into Cedar entities,
//! so the shape is controlled in one place — changing it changes every
//! downstream policy, which is exactly what compliance review needs.
//!
//! ## Entity namespaces used by Vortex
//!
//! - `User::"<uuid>"`  — a Vortex user. Attributes:
//!   - `username` (String)
//!   - `company_id` (String)
//! - `Role::"<role_name>"` — RBAC role. Users list these as `parents`,
//!   which lets policies use `principal in Role::"admin"`.
//! - `Company::"<uuid>"` — tenant scope.
//! - `Resource::"<type>:<id>"` — generic escape hatch for arbitrary
//!   resources. Used when the demo integration targets a user resource;
//!   future modules (change requests, POs) will add their own entity types
//!   (`ChangeRequest`, `PurchaseOrder`, etc.).
//!
//! Action entities are not built here — actions are just Cedar
//! `Action::"update"` string literals that the PolicyService constructs
//! from the action name passed by the caller.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};
use serde_json::Value;
use uuid::Uuid;

use crate::error::{PolicyError, PolicyResult};

/// The principal side of a policy check — a Vortex user with their role
/// memberships and tenant context.
#[derive(Debug, Clone)]
pub struct PolicyPrincipal {
    pub user_id: Uuid,
    pub username: String,
    pub company_id: Uuid,
    /// Role *names* (e.g. `"system_administrator"`). These are projected
    /// into `Role::"<name>"` parent entities so policies can use
    /// `principal in Role::"system_administrator"`.
    pub roles: Vec<String>,
}

/// The resource side of a policy check. Kept intentionally generic — the
/// `type_name` names the Cedar entity type, and `attributes` holds any
/// ABAC attributes the resource exposes (region, criticality, amount, etc.).
#[derive(Debug, Clone)]
pub struct PolicyResource {
    /// Cedar entity type, e.g. `"User"`, `"ChangeRequest"`, `"PurchaseOrder"`.
    pub type_name: String,
    /// Stable resource identifier. For user updates this is the target
    /// user's UUID; for change requests, the CR UUID; etc.
    pub id: String,
    /// Free-form ABAC attributes serialized as JSON. Only primitive types
    /// are currently projected into Cedar (strings, numbers, bools); the
    /// `owner_id` convention is special-cased to produce an entity
    /// reference.
    pub attributes: Value,
}

/// Build the complete entity list that Cedar needs for a single request.
///
/// This produces:
/// - The principal entity (with role parents)
/// - One entity per role the principal belongs to
/// - The company entity (as the principal's parent for tenant scoping)
/// - The resource entity (with flattened attributes)
///
/// The returned list is consumed by [`cedar_policy::Entities::from_entities`]
/// in the service layer.
pub fn build_entities(
    principal: &PolicyPrincipal,
    resource: &PolicyResource,
) -> PolicyResult<Vec<Entity>> {
    let mut entities: Vec<Entity> = Vec::new();

    // ─── Role entities ─────────────────────────────────────────────
    // One per role. These carry no attributes; the only thing policies
    // do with them is `principal in Role::"name"`, which requires the
    // role entity to exist in the entities set.
    let mut role_uids: HashSet<EntityUid> = HashSet::new();
    for role in &principal.roles {
        let uid = make_uid("Role", role)?;
        entities.push(
            Entity::new(uid.clone(), HashMap::new(), HashSet::new())
                .map_err(|e| PolicyError::EntityBuild(format!("Role entity: {e}")))?,
        );
        role_uids.insert(uid);
    }

    // ─── Company entity ────────────────────────────────────────────
    let company_uid = make_uid("Company", &principal.company_id.to_string())?;
    entities.push(
        Entity::new(company_uid.clone(), HashMap::new(), HashSet::new())
            .map_err(|e| PolicyError::EntityBuild(format!("Company entity: {e}")))?,
    );

    // ─── Principal (User) ──────────────────────────────────────────
    // Parents = all role uids + the company uid, so Cedar's `in` operator
    // can test both role membership and tenant scope.
    let principal_uid = make_uid("User", &principal.user_id.to_string())?;
    let mut principal_parents = role_uids.clone();
    principal_parents.insert(company_uid.clone());

    let mut principal_attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    principal_attrs.insert(
        "username".into(),
        RestrictedExpression::new_string(principal.username.clone()),
    );
    principal_attrs.insert(
        "company_id".into(),
        RestrictedExpression::new_string(principal.company_id.to_string()),
    );

    // ─── Resource ──────────────────────────────────────────────────
    // If the resource uid is identical to the principal uid (the
    // self-update case: a user editing their own profile), merge the
    // two rather than emitting duplicates. Cedar's entity set rejects
    // duplicates outright, so this is not optional.
    let resource_uid = make_uid(&resource.type_name, &resource.id)?;
    let resource_attrs = json_to_cedar_attrs(&resource.attributes)?;

    if resource_uid == principal_uid {
        // Merge: principal's attrs + resource's attrs, principal's parents.
        let mut merged_attrs = principal_attrs;
        for (k, v) in resource_attrs {
            merged_attrs.insert(k, v);
        }
        entities.push(
            Entity::new(principal_uid, merged_attrs, principal_parents)
                .map_err(|e| PolicyError::EntityBuild(format!("Self-resource entity: {e}")))?,
        );
    } else {
        entities.push(
            Entity::new(principal_uid, principal_attrs, principal_parents)
                .map_err(|e| PolicyError::EntityBuild(format!("Principal entity: {e}")))?,
        );
        entities.push(
            Entity::new(resource_uid, resource_attrs, HashSet::new())
                .map_err(|e| PolicyError::EntityBuild(format!("Resource entity: {e}")))?,
        );
    }

    Ok(entities)
}

/// Build a [`EntityUid`] from a type name and id. Cedar's `EntityId`
/// accepts an arbitrary string but the `EntityTypeName` must be a valid
/// identifier.
pub fn make_uid(type_name: &str, id: &str) -> PolicyResult<EntityUid> {
    let tn = EntityTypeName::from_str(type_name).map_err(|e| {
        PolicyError::EntityBuild(format!("invalid entity type '{type_name}': {e}"))
    })?;
    let eid = EntityId::from_str(id).map_err(|e| {
        PolicyError::EntityBuild(format!("invalid entity id '{id}': {e}"))
    })?;
    Ok(EntityUid::from_type_name_and_id(tn, eid))
}

/// Flatten a JSON object into a Cedar attribute map. Only primitive JSON
/// values become attributes — nested objects and arrays are skipped with
/// a warning, because Cedar's type system requires a schema to express
/// them and we don't ship one yet.
///
/// Future work: when schemas land, this function should honour nested
/// records and sets.
fn json_to_cedar_attrs(
    value: &Value,
) -> PolicyResult<HashMap<String, RestrictedExpression>> {
    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    if value.is_null() {
        return Ok(attrs);
    }
    let Value::Object(map) = value else {
        return Err(PolicyError::EntityBuild(
            "resource attributes must be a JSON object or null".into(),
        ));
    };

    for (key, val) in map {
        let expr = match val {
            Value::Null => continue,
            Value::Bool(b) => RestrictedExpression::new_bool(*b),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    RestrictedExpression::new_long(i)
                } else {
                    // Cedar doesn't have floats; skip.
                    continue;
                }
            }
            Value::String(s) => RestrictedExpression::new_string(s.clone()),
            Value::Array(_) | Value::Object(_) => continue,
        };
        attrs.insert(key.clone(), expr);
    }
    Ok(attrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_principal() -> PolicyPrincipal {
        PolicyPrincipal {
            user_id: Uuid::from_u128(1),
            username: "alice".into(),
            company_id: Uuid::from_u128(2),
            roles: vec!["system_administrator".into(), "auditor".into()],
        }
    }

    fn test_resource() -> PolicyResource {
        PolicyResource {
            type_name: "User".into(),
            id: Uuid::from_u128(3).to_string(),
            attributes: json!({ "username": "bob", "active": true, "login_count": 42 }),
        }
    }

    #[test]
    fn build_entities_includes_principal_resource_roles_and_company() {
        let p = test_principal();
        let r = test_resource();
        let entities = build_entities(&p, &r).unwrap();
        // 2 roles + 1 company + 1 principal + 1 resource = 5
        assert_eq!(entities.len(), 5);
    }

    #[test]
    fn nested_attributes_are_skipped() {
        let p = test_principal();
        let r = PolicyResource {
            type_name: "WorkOrder".into(),
            id: "wo-1".into(),
            attributes: json!({
                "priority": 3,
                "tags": ["urgent", "critical"],   // skipped
                "nested": { "a": 1 },             // skipped
                "name": "Oil change"
            }),
        };
        // Should not error — nested values are silently dropped.
        let _ = build_entities(&p, &r).unwrap();
    }

    #[test]
    fn null_attributes_work() {
        let p = test_principal();
        let r = PolicyResource {
            type_name: "User".into(),
            id: "u1".into(),
            attributes: Value::Null,
        };
        let _ = build_entities(&p, &r).unwrap();
    }

    #[test]
    fn non_object_attributes_error() {
        let p = test_principal();
        let r = PolicyResource {
            type_name: "User".into(),
            id: "u1".into(),
            attributes: json!("a string"),
        };
        assert!(build_entities(&p, &r).is_err());
    }
}
