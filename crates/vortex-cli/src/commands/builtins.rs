//! Synthetic "built-in" plugins owned by the host binary itself.
//!
//! These are not real plugin crates. They are lightweight [`Plugin`]
//! implementations registered inline in `server.rs` that exist to
//! feed the plugin registry with menu entries for **features whose
//! handlers still live in the host binary**. They are a transitional
//! seam, not a long-term design.
//!
//! ## Why this exists
//!
//! Phase 0.5 created `crates/vortex-change/` as a real plugin crate.
//! But a handful of historical
//! modules — Contacts in particular — still have their HTTP handlers
//! hardcoded in `crates/vortex-cli/src/commands/server.rs` because
//! moving them is a separate project.
//!
//! Before Phase 0.6 the sidebar had a hardcoded
//! `if installed.contains("contacts")` check inside the framework
//! crate, which meant the framework knew about a specific module by
//! name. That violates the "framework has no plugin knowledge"
//! invariant. The synthetic `ContactsBuiltinPlugin` here replaces
//! that hack: the host binary registers it like any other plugin,
//! the framework iterates plugins uniformly, and the sidebar
//! composition stays data-driven.
//!
//! When Contacts is eventually extracted into `crates/vortex-contacts/`
//! with its own handlers + migrations, delete this file and register
//! the real plugin instead. The change is local to `server.rs`.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tracing::{error, info, warn};
use vortex_framework::scheduler::{Schedule, ScheduledAction, ScheduledActionDef};
use vortex_framework::{AppState, MenuEntry, MenuGroup, Plugin};
use vortex_security::audit::verify::{verify_chain, VerifyOptions};
use vortex_security::{AuditAction, AuditEntry, AuditSeverity};

/// Synthetic plugin for the built-in Contacts module. Contributes
/// the sidebar entry only — the actual HTTP handlers are still
/// registered directly in `server.rs::build_router` and will stay
/// there until Contacts is extracted into its own crate.
pub struct ContactsBuiltinPlugin;

impl Plugin for ContactsBuiltinPlugin {
    fn technical_name(&self) -> &'static str {
        "contacts"
    }

    fn display_name(&self) -> &'static str {
        "Contacts"
    }

    fn version(&self) -> &'static str {
        // Tracks the host binary version, not an independent
        // release — this is a synthetic plugin, not a real module.
        env!("CARGO_PKG_VERSION")
    }

    /// No routes — the real handlers are registered inline in
    /// `server.rs::build_router`. Returning an empty router here is
    /// correct; the merge is a no-op.
    fn routes(&self) -> Router<Arc<AppState>> {
        Router::new()
    }

    /// One sidebar entry under Operations. The framework filters
    /// entries by install state (`installed_modules`) before
    /// rendering, so Contacts still vanishes from the sidebar if an
    /// admin uninstalls it through the module manager.
    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![MenuEntry::new(
            "contacts.list",
            "Contacts",
            "/contacts",
            MenuGroup::Operations,
        )
        .with_icon("users")
        .with_priority(10)]
    }
}

/// Synthetic plugin owning host-wide system jobs. Today the only
/// contribution is the daily WORM audit chain verification scheduled
/// action — a platform-level compliance task that doesn't belong to
/// any business-domain plugin but needs to run via the same
/// `Plugin::scheduled_actions()` pipeline the framework already uses
/// for everything else.
///
/// This plugin has no routes and no sidebar entries — it exists
/// purely to carry the scheduled action into the plugin registry.
/// If future system jobs land (key rotation, orphan-session cleanup,
/// stale-session sweep, retention purges), they join the `Vec` this
/// plugin returns from `scheduled_actions()`.
pub struct SystemBuiltinPlugin;

impl Plugin for SystemBuiltinPlugin {
    fn technical_name(&self) -> &'static str {
        "system"
    }

    fn display_name(&self) -> &'static str {
        "System"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// No routes.
    fn routes(&self) -> Router<Arc<AppState>> {
        Router::new()
    }

    /// No sidebar entries — the System plugin is invisible to end
    /// users. Administrators inspect system jobs via the
    /// `scheduled_actions` table or the future admin UI.
    fn menu_entries(&self) -> Vec<MenuEntry> {
        Vec::new()
    }

    /// One scheduled action: the nightly WORM chain verification
    /// self-attestation. Closes the gap in Phase 0.1 where chain
    /// verification was CLI-only and required an operator to run
    /// `vortex audit verify` on a cron outside the application.
    ///
    /// Run cadence: every 24 hours. The first run happens at the
    /// next scheduler poll tick after startup (because the sync
    /// code inserts rows with `next_call = NOW()`), so a fresh
    /// install immediately self-attests before it has any
    /// interesting data to tamper with — establishing a baseline.
    ///
    /// The handler uses [`verify_chain`] — the same library
    /// function the `vortex audit verify` CLI calls — so the two
    /// verification paths cannot drift.
    fn scheduled_actions(&self) -> Vec<ScheduledAction> {
        vec![ScheduledAction::new(
            ScheduledActionDef {
                code: "system.audit_chain_verify",
                name: "System: WORM audit chain verification",
                schedule: Schedule::Every(Duration::from_secs(24 * 60 * 60)),
                enabled_by_default: true,
            },
            |state| async move {
                info!("scheduled audit chain verification: starting");

                // Library call — read-only walk of the chain.
                let report = verify_chain(&state.db, &VerifyOptions::default())
                    .await
                    .map_err(|e| {
                        error!(error = %e, "audit chain verification query failed");
                        e
                    })?;

                // Write the self-attestation into the WORM ledger.
                // Success → ChainVerificationPassed (Info).
                // Failure → ChainVerificationFailed (Critical) — the
                // `is_critical()` classifier fires the alert handler,
                // and the critical severity makes it impossible to
                // miss in audit exports.
                //
                // Either way we emit exactly one attestation per run.
                // The attestation itself becomes part of the chain
                // and the next day's verification will observe it
                // alongside the business events.
                if report.ok() {
                    let entry = AuditEntry::new(
                        AuditAction::ChainVerificationPassed,
                        AuditSeverity::Info,
                    )
                    .with_resource("audit_chain", "all")
                    .with_details(serde_json::json!({
                        "companies_checked": report.companies_checked,
                        "entries_verified": report.entries_verified,
                        "duration_ms": report.duration.as_millis() as u64,
                    }));

                    info!(
                        entries_verified = report.entries_verified as i64,
                        companies_checked = report.companies_checked as i64,
                        duration_ms = report.duration.as_millis() as i64,
                        "scheduled audit chain verification: passed"
                    );

                    if let Err(e) = state.audit.log(entry).await {
                        error!(
                            error = %e,
                            "failed to write ChainVerificationPassed attestation"
                        );
                        return Err(e);
                    }
                } else {
                    // Aggregate failure kinds for a structured summary
                    // in the audit payload — the detail strings alone
                    // would blow past any sensible field length if the
                    // chain is comprehensively broken.
                    let mut kind_counts: std::collections::HashMap<&'static str, i64> =
                        std::collections::HashMap::new();
                    for f in &report.failures {
                        *kind_counts.entry(f.kind.code()).or_insert(0) += 1;
                    }

                    // Keep only the first 10 detail strings in the
                    // payload so the audit entry stays bounded.
                    let sample: Vec<serde_json::Value> = report
                        .failures
                        .iter()
                        .take(10)
                        .map(|f| {
                            serde_json::json!({
                                "company_id": f.company_id.to_string(),
                                "chain_position": f.chain_position,
                                "entry_id": f.entry_id.to_string(),
                                "kind": f.kind.code(),
                                "detail": f.detail,
                            })
                        })
                        .collect();

                    let entry = AuditEntry::new(
                        AuditAction::ChainVerificationFailed,
                        AuditSeverity::Critical,
                    )
                    .with_resource("audit_chain", "all")
                    .with_error(format!("{} failures detected", report.failure_count()))
                    .with_details(serde_json::json!({
                        "companies_checked": report.companies_checked,
                        "entries_verified": report.entries_verified,
                        "failure_count": report.failure_count(),
                        "kind_counts": kind_counts,
                        "sample_failures": sample,
                        "duration_ms": report.duration.as_millis() as u64,
                    }));

                    // This is the loud one. A broken WORM chain is
                    // an incident — error-level tracing so any log
                    // aggregator paging on error severity catches it,
                    // plus a critical audit entry so operators see it
                    // in the next export run.
                    error!(
                        failure_count = report.failure_count() as i64,
                        entries_verified = report.entries_verified as i64,
                        companies_checked = report.companies_checked as i64,
                        "SCHEDULED AUDIT CHAIN VERIFICATION FAILED — chain integrity break"
                    );
                    for f in report.failures.iter().take(10) {
                        warn!(
                            company_id = %f.company_id,
                            chain_position = f.chain_position,
                            entry_id = %f.entry_id,
                            kind = f.kind.code(),
                            detail = %f.detail,
                            "chain verification failure"
                        );
                    }

                    if let Err(e) = state.audit.log(entry).await {
                        error!(
                            error = %e,
                            "failed to write ChainVerificationFailed attestation"
                        );
                        return Err(e);
                    }
                }

                // The scheduled action itself always returns Ok — the
                // *check* ran successfully, regardless of what it
                // found. Returning Err here would mark the action as
                // having failed, pollute `scheduled_actions.last_error`
                // with the chain problem, and confuse the operational
                // signal. The chain problem is communicated via the
                // audit event, not via the scheduler run status.
                Ok(())
            },
        )]
    }
}
