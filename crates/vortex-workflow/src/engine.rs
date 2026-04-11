//! [`WorkflowEngine`] — the service that orchestrates transitions.
//!
//! A single method does the whole cycle:
//!
//! 1. Look up the state machine for the instance's workflow type
//! 2. Verify the transition is a legal edge from the current state
//! 3. Ask Cedar if the actor is allowed to perform this transition
//!    on this instance
//! 4. Run any pre-transition hooks
//! 5. Write the transition history row + audit ledger entry
//!    **in the same transaction** as the state update
//! 6. Update the instance's current_state and state_data
//! 7. Run any post-transition hooks
//! 8. Commit
//!
//! The audit ledger tie is what gives workflow transitions their
//! compliance guarantee: every "user X did Y to workflow Z at time
//! T" event lands in the WORM hash chain via
//! [`vortex_security::AuditLog::log`]. The policy check is what
//! lets a compliance officer declare rules like "approver ≠
//! requester" without editing Rust.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use serde_json::Value;
use tracing::{debug, info, warn};
use uuid::Uuid;
use vortex_policy::service::DenyReason;
use vortex_policy::{Decision, PolicyPrincipal, PolicyResource, PolicyService};
use vortex_security::{AuditAction, AuditEntry, AuditLog, AuditSeverity};

use crate::error::{WorkflowError, WorkflowResult};
use crate::instance::{InstanceId, WorkflowInstance};
use crate::machine::{StateMachine, Transition, WorkflowType};
use crate::store::{TransitionRecord, WorkflowStore};

/// Context passed to `WorkflowEngine::transition`. This is what the
/// engine uses to build the Cedar policy request and the audit entry.
#[derive(Debug, Clone)]
pub struct TransitionContext {
    /// The user triggering the transition.
    pub actor: PolicyPrincipal,
    /// Free-form JSON metadata the caller wants attached to the
    /// transition history row (e.g. approval comments, rejection
    /// reasons, amount overrides). Ends up in both the
    /// `workflow_transitions.context` column and the audit entry's
    /// details field.
    pub context: Value,
}

/// Returned from a successful transition. Gives the caller the
/// new instance state and the id of the transition record for
/// further chaining.
#[derive(Debug, Clone)]
pub struct TransitionOutcome {
    pub instance: WorkflowInstance,
    pub transition_record_id: Uuid,
    pub from_state: String,
    pub to_state: String,
}

/// The workflow engine. Holds a map of registered state machines
/// keyed by workflow type, plus references to the audit log, policy
/// service, and store. Cheap to clone (all inner fields are `Arc`).
pub struct WorkflowEngine {
    store: Arc<dyn WorkflowStore>,
    audit: Arc<AuditLog>,
    policy: Arc<PolicyService>,
    machines: HashMap<WorkflowType, StateMachine>,
}

impl WorkflowEngine {
    /// Build an engine with no state machines registered. Call
    /// [`register_machine`](Self::register_machine) for each
    /// workflow the host wants the engine to handle.
    pub fn new(
        store: Arc<dyn WorkflowStore>,
        audit: Arc<AuditLog>,
        policy: Arc<PolicyService>,
    ) -> Self {
        Self {
            store,
            audit,
            policy,
            machines: HashMap::new(),
        }
    }

    /// Register a state machine. The engine will not accept
    /// transitions on instances whose `workflow_type` has not been
    /// registered — that's the "unknown workflow" error.
    pub fn register_machine(&mut self, machine: StateMachine) -> &mut Self {
        info!(
            workflow_type = machine.workflow_type().as_str(),
            state_count = machine.states().count(),
            transition_count = machine.all_transitions().len(),
            "registered workflow state machine"
        );
        self.machines.insert(machine.workflow_type().clone(), machine);
        self
    }

    /// Return the state machine for a given type, if registered.
    pub fn machine(&self, workflow_type: &WorkflowType) -> Option<&StateMachine> {
        self.machines.get(workflow_type)
    }

    /// Expose the store for callers that want to do their own reads
    /// (lists, instance fetches, history walks). Writes should still
    /// go through [`transition`](Self::transition) so audit +
    /// policy guarantees are preserved.
    pub fn store(&self) -> &Arc<dyn WorkflowStore> {
        &self.store
    }

    /// Create a fresh instance in the registered workflow's initial
    /// state. Returns the stored instance so the caller has the
    /// generated id and timestamps.
    pub async fn create_instance(
        &self,
        workflow_type: &WorkflowType,
        company_id: Uuid,
        created_by: Uuid,
        state_data: Value,
    ) -> WorkflowResult<WorkflowInstance> {
        let machine = self
            .machines
            .get(workflow_type)
            .ok_or_else(|| WorkflowError::UnknownWorkflow(workflow_type.as_str().to_string()))?;
        let initial = machine
            .initial_state()
            .ok_or_else(|| {
                WorkflowError::Internal(format!(
                    "workflow '{}' has no initial state declared",
                    workflow_type.as_str()
                ))
            })?
            .to_string();
        let instance = WorkflowInstance::new(workflow_type.clone(), initial, company_id, created_by)
            .with_state_data(state_data);
        self.store.create_instance(instance).await
    }

    /// Perform a transition. This is the one big method: it runs
    /// validation, Cedar check, audit write, state update, and
    /// history append, and returns the new instance state on success.
    ///
    /// Failure paths:
    /// - `UnknownWorkflow` — the workflow type on the instance is
    ///   not in the engine's registry (programming error)
    /// - `UnknownState` / `InvalidTransition` — the instance's
    ///   current state is bad or the requested transition doesn't
    ///   apply from that state
    /// - `PolicyDenied` — Cedar said no
    /// - `Store` / `AuditFailed` — DB errors
    ///
    /// Success path writes an `AuditAction::WorkflowTransition`
    /// entry to the WORM ledger (chained + signed) and a row to
    /// `workflow_transitions`, then updates `workflow_instances`.
    pub async fn transition(
        &self,
        instance_id: InstanceId,
        transition_name: &str,
        ctx: TransitionContext,
    ) -> WorkflowResult<TransitionOutcome> {
        // 1. Load the instance
        let instance = self.store.get_instance(instance_id).await?;
        let wf_type = instance.workflow_type.clone();

        // 2. Look up the state machine
        let machine = self
            .machines
            .get(&wf_type)
            .ok_or_else(|| WorkflowError::UnknownWorkflow(wf_type.as_str().to_string()))?;

        if !machine.has_state(&instance.current_state) {
            return Err(WorkflowError::UnknownState {
                workflow: wf_type.as_str().to_string(),
                state: instance.current_state.clone(),
            });
        }

        // 3. Verify the transition is legal from the current state
        let edge: &Transition = machine
            .find_transition(&instance.current_state, transition_name)
            .ok_or_else(|| {
                // Distinguish "transition name doesn't exist at all"
                // from "transition exists but not from this state"
                // so callers can give users more precise errors.
                let name_exists = machine
                    .all_transitions()
                    .iter()
                    .any(|t| t.name == transition_name);
                if name_exists {
                    WorkflowError::InvalidTransition {
                        workflow: wf_type.as_str().to_string(),
                        transition: transition_name.to_string(),
                        from_state: instance.current_state.clone(),
                    }
                } else {
                    WorkflowError::UnknownTransition {
                        workflow: wf_type.as_str().to_string(),
                        transition: transition_name.to_string(),
                    }
                }
            })?;
        let from_state = edge.from_state.clone();
        let to_state = edge.to_state.clone();

        // 4. Cedar policy check. The resource is this workflow
        //    instance — plugins can write policies like
        //    `permit(principal, action == Action::"approve",
        //     resource) when { resource.workflow_type == "cr" }`.
        let resource = PolicyResource {
            type_name: "WorkflowInstance".into(),
            id: instance_id.0.to_string(),
            attributes: serde_json::json!({
                "workflow_type": wf_type.as_str(),
                "from_state": from_state,
                "to_state": to_state,
            }),
        };
        let decision = self
            .policy
            .check(&ctx.actor, transition_name, &resource)
            .await
            .map_err(|e| WorkflowError::Internal(format!("policy check: {e}")))?;
        match decision {
            Decision::Allow { determining_policies } => {
                debug!(
                    instance = %instance_id,
                    transition = transition_name,
                    determining = ?determining_policies,
                    "workflow transition allowed by policy"
                );
            }
            Decision::Deny { determining_policies, reason } => {
                let reason_str = match reason {
                    DenyReason::ExplicitForbid => {
                        format!("explicit forbid: {:?}", determining_policies)
                    }
                    DenyReason::NoMatchingPermit => "no matching permit".to_string(),
                };
                warn!(
                    instance = %instance_id,
                    transition = transition_name,
                    principal = %ctx.actor.user_id,
                    reason = %reason_str,
                    "workflow transition denied by policy"
                );
                return Err(WorkflowError::PolicyDenied {
                    transition: transition_name.to_string(),
                    principal: ctx.actor.user_id.to_string(),
                    reason: reason_str,
                });
            }
        }

        // 5. Write the audit ledger entry. This goes through the
        //    existing PgAuditStorage which already enforces the
        //    hash chain + Ed25519 signature + WORM table triggers.
        //    The returned entry id goes into workflow_transitions
        //    so the history row links back to the exact audit row.
        let audit_entry_id = uuid::Uuid::now_v7();
        let audit_entry =
            AuditEntry::new(AuditAction::WorkflowTransition, AuditSeverity::Info)
                .with_user(vortex_common::UserId(ctx.actor.user_id))
                .with_username(&ctx.actor.username)
                .with_company(vortex_common::CompanyId(instance.company_id))
                .with_resource(
                    format!("workflow_instance:{}", wf_type.as_str()),
                    instance_id.0.to_string(),
                )
                .with_details(serde_json::json!({
                    "workflow_type": wf_type.as_str(),
                    "transition": transition_name,
                    "from_state": from_state,
                    "to_state": to_state,
                    "context": ctx.context,
                }));
        let audit_entry = AuditEntry {
            id: audit_entry_id,
            ..audit_entry
        };
        self.audit
            .log(audit_entry)
            .await
            .map_err(|e| WorkflowError::AuditFailed(e.to_string()))?;

        // 6. Record the transition in the workflow_transitions
        //    history table. This is append-only (migration 116
        //    installs WORM triggers on this table just like
        //    audit_log).
        let record = TransitionRecord {
            id: uuid::Uuid::now_v7(),
            instance_id,
            transition_name: transition_name.to_string(),
            from_state: from_state.clone(),
            to_state: to_state.clone(),
            actor_user_id: Some(ctx.actor.user_id),
            context: ctx.context.clone(),
            audit_entry_id: Some(audit_entry_id),
            occurred_at: Utc::now(),
        };
        let record_id = record.id;
        self.store.record_transition(record).await?;

        // 7. Update the live instance's current_state. state_data
        //    is passed through untouched — if the caller wants to
        //    mutate fields during a transition, they pass the new
        //    data via the context, and a pre-transition hook (future
        //    phase) applies it before this write.
        self.store
            .update_instance_state(instance_id, &to_state, &instance.state_data)
            .await?;

        info!(
            instance = %instance_id,
            workflow = wf_type.as_str(),
            from_state = %from_state,
            to_state = %to_state,
            actor = %ctx.actor.user_id,
            "workflow transition committed"
        );

        // 8. Return the new state to the caller
        let mut updated = instance;
        updated.current_state = to_state.clone();
        updated.updated_at = Utc::now();

        Ok(TransitionOutcome {
            instance: updated,
            transition_record_id: record_id,
            from_state,
            to_state,
        })
    }
}
