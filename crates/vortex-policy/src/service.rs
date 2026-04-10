//! [`PolicyService`] — the top-level entry point.
//!
//! Handlers hold an `Arc<PolicyService>` and call [`PolicyService::check`]
//! to get an `Allow` / `Deny` decision. The service is cheap to clone
//! (all fields are `Arc`) and safe to share across all request tasks.
//!
//! ## Lifecycle
//!
//! 1. Startup: `PolicyService::load(store).await` reads every active
//!    policy row, parses each as Cedar source, and assembles a
//!    `cedar_policy::PolicySet`. Parse errors are logged per-policy but
//!    do not abort startup — a bad policy should not take the whole
//!    server down. The bad policy's id and error are surfaced via
//!    [`PolicyService::parse_errors`] so an admin command can list them.
//! 2. Request path: `check` builds the entity set (see `entities.rs`),
//!    constructs a `Request`, and calls `Authorizer::is_authorized`.
//! 3. Reload: `PolicyService::reload` re-reads the store and swaps the
//!    policy set atomically.
//!
//! ## Decision semantics
//!
//! Cedar's semantics are **deny-by-default with explicit forbid**: if no
//! policy `permit`s the action, the result is `Deny`. If any policy
//! `forbid`s it, the result is `Deny` regardless of other permits. This
//! is what you want for a compliance-grade policy engine — the default
//! answer to *"can Alice do this?"* is always *no* unless a policy
//! explicitly says yes.

use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, PolicyId, PolicySet, Request,
};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::entities::{build_entities, make_uid, PolicyPrincipal, PolicyResource};
use crate::error::{PolicyError, PolicyResult};
use crate::store::{PolicyRecord, PolicyStore};

/// The outcome of a policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Cedar decided the action is permitted. The `determining_policies`
    /// list contains the ids of the `permit` policies that matched.
    Allow {
        determining_policies: Vec<String>,
    },
    /// Cedar decided the action is denied. For explicit denies the
    /// `determining_policies` contains the `forbid` policy ids; for
    /// implicit (no-permit-matched) denies it is empty.
    Deny {
        determining_policies: Vec<String>,
        reason: DenyReason,
    },
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// At least one `forbid` policy matched.
    ExplicitForbid,
    /// No `permit` policy matched. This is the deny-by-default path and
    /// is the outcome most operators see first.
    NoMatchingPermit,
}

/// Per-policy parse error surfaced via [`PolicyService::parse_errors`].
#[derive(Debug, Clone)]
pub struct ParseErrorEntry {
    pub policy_db_id: Uuid,
    pub policy_name: String,
    pub error: String,
}

/// The policy service.
pub struct PolicyService {
    store: Arc<dyn PolicyStore>,
    inner: RwLock<PolicyInner>,
}

struct PolicyInner {
    /// The assembled Cedar policy set used for every decision.
    policy_set: PolicySet,
    /// Map from Cedar PolicyId (the DB uuid, as a string) back to the
    /// friendly name so `Decision` can surface names instead of uuids.
    name_index: std::collections::HashMap<String, String>,
    /// Any policies that failed to parse during load, for operator
    /// visibility.
    parse_errors: Vec<ParseErrorEntry>,
}

impl PolicyService {
    /// Build a service from any [`PolicyStore`]. Does not perform I/O —
    /// call [`PolicyService::reload`] to populate the initial policy
    /// set. Unit tests that provide an in-memory store typically call
    /// [`PolicyService::load`] directly.
    pub fn new(store: Arc<dyn PolicyStore>) -> Self {
        Self {
            store,
            inner: RwLock::new(PolicyInner {
                policy_set: PolicySet::new(),
                name_index: Default::default(),
                parse_errors: Vec::new(),
            }),
        }
    }

    /// Convenience: construct and load in one call.
    pub async fn load(store: Arc<dyn PolicyStore>) -> PolicyResult<Self> {
        let svc = Self::new(store);
        svc.reload().await?;
        Ok(svc)
    }

    /// Re-read policies from the store and swap the policy set.
    ///
    /// Policies that fail to parse are logged and accumulated in
    /// `parse_errors`; they do not abort the reload. This matches the
    /// design principle that the server must never go down because one
    /// admin pasted a bad policy.
    pub async fn reload(&self) -> PolicyResult<()> {
        let records = self.store.load_all().await?;
        let (policy_set, name_index, parse_errors) = assemble_policy_set(&records);

        let mut guard = self.inner.write().await;
        guard.policy_set = policy_set;
        guard.name_index = name_index;
        guard.parse_errors = parse_errors;

        info!(
            policy_count = records.len() as i64,
            parse_errors = guard.parse_errors.len() as i64,
            "policy service reloaded"
        );
        Ok(())
    }

    /// Return any parse errors from the most recent load. Useful for a
    /// future admin page that shows operators which policies are broken.
    pub async fn parse_errors(&self) -> Vec<ParseErrorEntry> {
        self.inner.read().await.parse_errors.clone()
    }

    /// Perform an authorization check.
    ///
    /// `action_name` is a bare string like `"update"`, `"approve"`, or
    /// `"delete"` — the service constructs the `Action::"<name>"`
    /// EntityUid internally.
    pub async fn check(
        &self,
        principal: &PolicyPrincipal,
        action_name: &str,
        resource: &PolicyResource,
    ) -> PolicyResult<Decision> {
        // Build entities
        let entity_vec = build_entities(principal, resource)?;
        let entities = Entities::from_entities(entity_vec, None)
            .map_err(|e| PolicyError::EntityBuild(format!("Entities::from_entities: {e}")))?;

        // EntityUid for principal, action, resource
        let principal_uid = make_uid("User", &principal.user_id.to_string())?;
        let action_uid = make_uid("Action", action_name)?;
        let resource_uid = make_uid(&resource.type_name, &resource.id)?;

        // Empty context for now. Future work: pass request-scoped data
        // (time of day, source IP, MFA level, etc.) here so policies can
        // condition on it.
        let context = Context::empty();

        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            context,
            None,
        )
        .map_err(|e| PolicyError::RequestBuild(e.to_string()))?;

        let inner = self.inner.read().await;
        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&request, &inner.policy_set, &entities);

        // Map Cedar response → Vortex Decision, translating policy ids
        // back to friendly names.
        let determining_ids: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|pid| {
                let pid_str = pid.to_string();
                inner
                    .name_index
                    .get(&pid_str)
                    .cloned()
                    .unwrap_or(pid_str)
            })
            .collect();

        let decision = match response.decision() {
            CedarDecision::Allow => Decision::Allow {
                determining_policies: determining_ids,
            },
            CedarDecision::Deny => {
                let reason = if determining_ids.is_empty() {
                    DenyReason::NoMatchingPermit
                } else {
                    DenyReason::ExplicitForbid
                };
                Decision::Deny {
                    determining_policies: determining_ids,
                    reason,
                }
            }
        };

        debug!(
            principal = %principal.user_id,
            action = action_name,
            resource_type = %resource.type_name,
            resource_id = %resource.id,
            allow = decision.is_allow(),
            "policy check"
        );

        Ok(decision)
    }
}

fn assemble_policy_set(
    records: &[PolicyRecord],
) -> (
    PolicySet,
    std::collections::HashMap<String, String>,
    Vec<ParseErrorEntry>,
) {
    let mut policy_set = PolicySet::new();
    let mut name_index = std::collections::HashMap::new();
    let mut parse_errors = Vec::new();

    for record in records {
        // Parse the source as a PolicySet (Cedar source can contain
        // multiple `permit`/`forbid` statements per row, though in
        // practice we keep one statement per row for clarity and audit).
        match PolicySet::from_str(&record.policy_text) {
            Ok(parsed) => {
                // Tag each parsed policy with the record's DB id so the
                // determining-policies list can be mapped back.
                for policy in parsed.policies() {
                    // Use the DB uuid as the PolicyId for stability. If a
                    // single DB row contains multiple statements, suffix
                    // each with the original Cedar policy id so we don't
                    // collide inside the aggregated PolicySet.
                    let original_id = policy.id().to_string();
                    let aggregated_id = if original_id == "policy0" {
                        record.id.to_string()
                    } else {
                        format!("{}__{}", record.id, original_id)
                    };
                    let new_id = PolicyId::new(&aggregated_id);
                    let relabeled = policy.new_id(new_id);
                    if let Err(e) = policy_set.add(relabeled) {
                        warn!(
                            policy_name = %record.name,
                            error = %e,
                            "duplicate policy id; skipping"
                        );
                        continue;
                    }
                    name_index.insert(aggregated_id, record.name.clone());
                }
            }
            Err(e) => {
                error!(
                    policy_name = %record.name,
                    error = %e,
                    "policy failed to parse; will be excluded from policy set"
                );
                parse_errors.push(ParseErrorEntry {
                    policy_db_id: record.id,
                    policy_name: record.name.clone(),
                    error: e.to_string(),
                });
            }
        }
    }

    (policy_set, name_index, parse_errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{test_record, InMemoryPolicyStore};

    fn test_principal(roles: &[&str]) -> PolicyPrincipal {
        PolicyPrincipal {
            user_id: Uuid::from_u128(1),
            username: "alice".into(),
            company_id: Uuid::from_u128(100),
            roles: roles.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn test_resource() -> PolicyResource {
        PolicyResource {
            type_name: "User".into(),
            id: Uuid::from_u128(2).to_string(),
            attributes: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn empty_policy_set_denies_everything() {
        let store = Arc::new(InMemoryPolicyStore::with(vec![]));
        let svc = PolicyService::load(store).await.unwrap();
        let p = test_principal(&[]);
        let r = test_resource();
        let decision = svc.check(&p, "update", &r).await.unwrap();
        assert!(decision.is_deny());
        if let Decision::Deny { reason, .. } = decision {
            assert_eq!(reason, DenyReason::NoMatchingPermit);
        }
    }

    #[tokio::test]
    async fn admin_role_permits_user_update() {
        let store = Arc::new(InMemoryPolicyStore::with(vec![test_record(
            Uuid::from_u128(9001),
            "admins_can_manage_users",
            r#"permit (
                principal in Role::"system_administrator",
                action == Action::"update",
                resource
            );"#,
            10,
        )]));
        let svc = PolicyService::load(store).await.unwrap();

        // Admin principal: allowed.
        let admin = test_principal(&["system_administrator"]);
        let r = test_resource();
        assert!(svc.check(&admin, "update", &r).await.unwrap().is_allow());

        // Non-admin: denied.
        let user = test_principal(&["viewer"]);
        assert!(svc.check(&user, "update", &r).await.unwrap().is_deny());
    }

    #[tokio::test]
    async fn self_update_permit() {
        // User can update themselves regardless of role.
        let store = Arc::new(InMemoryPolicyStore::with(vec![test_record(
            Uuid::from_u128(9002),
            "self_service_profile",
            r#"permit (
                principal,
                action == Action::"update",
                resource
            ) when {
                principal == resource
            };"#,
            20,
        )]));
        let svc = PolicyService::load(store).await.unwrap();

        let alice = PolicyPrincipal {
            user_id: Uuid::from_u128(42),
            username: "alice".into(),
            company_id: Uuid::from_u128(100),
            roles: vec!["viewer".into()],
        };
        // Alice updating Alice → allow.
        let self_resource = PolicyResource {
            type_name: "User".into(),
            id: Uuid::from_u128(42).to_string(),
            attributes: serde_json::Value::Null,
        };
        assert!(svc
            .check(&alice, "update", &self_resource)
            .await
            .unwrap()
            .is_allow());

        // Alice updating someone else → deny.
        let other_resource = PolicyResource {
            type_name: "User".into(),
            id: Uuid::from_u128(43).to_string(),
            attributes: serde_json::Value::Null,
        };
        assert!(svc
            .check(&alice, "update", &other_resource)
            .await
            .unwrap()
            .is_deny());
    }

    #[tokio::test]
    async fn forbid_beats_permit() {
        let store = Arc::new(InMemoryPolicyStore::with(vec![
            test_record(
                Uuid::from_u128(9003),
                "admins_allow",
                r#"permit (
                    principal in Role::"system_administrator",
                    action,
                    resource
                );"#,
                10,
            ),
            test_record(
                Uuid::from_u128(9004),
                "never_delete_audit_log",
                r#"forbid (
                    principal,
                    action == Action::"delete",
                    resource == User::"00000000-0000-0000-0000-000000000000"
                );"#,
                1,
            ),
        ]));
        let svc = PolicyService::load(store).await.unwrap();

        let admin = test_principal(&["system_administrator"]);
        let protected = PolicyResource {
            type_name: "User".into(),
            id: "00000000-0000-0000-0000-000000000000".into(),
            attributes: serde_json::Value::Null,
        };
        let decision = svc.check(&admin, "delete", &protected).await.unwrap();
        assert!(decision.is_deny());
        if let Decision::Deny { reason, .. } = decision {
            assert_eq!(reason, DenyReason::ExplicitForbid);
        }
    }

    #[tokio::test]
    async fn bad_policy_does_not_break_reload() {
        let store = Arc::new(InMemoryPolicyStore::with(vec![
            test_record(
                Uuid::from_u128(9005),
                "good_policy",
                r#"permit (principal, action, resource);"#,
                10,
            ),
            test_record(
                Uuid::from_u128(9006),
                "syntactically_broken",
                r#"this is not a valid cedar policy"#,
                20,
            ),
        ]));
        let svc = PolicyService::load(store).await.unwrap();
        let errors = svc.parse_errors().await;
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].policy_name, "syntactically_broken");

        // Good policy still works.
        let p = test_principal(&[]);
        let r = test_resource();
        assert!(svc.check(&p, "view", &r).await.unwrap().is_allow());
    }
}
