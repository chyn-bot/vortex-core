//! Acceptance tests for the DAMS / TAMS division boundary (spec §6.3).
//!
//! The build spec requires an explicit test that **a DAMS principal cannot
//! reach a transmission record by ID** — and, crucially, that such a fetch
//! fails as *Forbidden*, not as an empty / not-found result that would leak a
//! different signal for "exists elsewhere" vs "does not exist".
//!
//! These exercise the shipped enforcement logic end-to-end from role claims:
//! `AuthUser.roles → DivisionScope → { list predicate, fetch-by-id decision }`.
//! The DB-backed derivation (migration 009's trigger) and the live lookup query
//! are thin wrappers over this decision, which is what the boundary hinges on.

use vortex_plugin_sdk::uuid::Uuid;
use vortex_sesb_eam::handlers::division::{
    division_predicate, guard_decision, DivisionScope, GuardOutcome, DIST, TRANS,
};

fn user(roles: &[&str]) -> vortex_plugin_sdk::prelude::AuthUser {
    vortex_plugin_sdk::prelude::AuthUser {
        id: Uuid::nil(),
        username: "t".into(),
        full_name: None,
        session_id: Uuid::nil(),
        roles: roles.iter().map(|s| s.to_string()).collect(),
        contact_id: None,
        is_portal: false,
    }
}

/// THE required test: a DAMS user addressing a transmission record by ID is
/// refused with Forbidden — not NotFound, not an empty success.
#[test]
fn dams_cannot_reach_a_transmission_record_by_id() {
    let dams = user(&["EAM User", "EAM DAMS"]);
    let scope = DivisionScope::for_user(&dams);

    // The row exists and is transmission.
    let outcome = guard_decision(scope, Some(Some(TRANS)));
    assert_eq!(
        outcome,
        GuardOutcome::Forbidden,
        "a DAMS principal must be *forbidden* (not silently 404'd) from a transmission row"
    );
    assert_ne!(outcome, GuardOutcome::NotFound);
    assert_ne!(outcome, GuardOutcome::Allowed);
}

/// The same boundary, symmetric for TAMS reaching a distribution record.
#[test]
fn tams_cannot_reach_a_distribution_record_by_id() {
    let tams = user(&["EAM User", "EAM TAMS"]);
    let scope = DivisionScope::for_user(&tams);
    assert_eq!(guard_decision(scope, Some(Some(DIST))), GuardOutcome::Forbidden);
}

/// A DAMS user *can* reach distribution and unset rows; a genuinely missing row
/// is NotFound (so the two failure modes stay distinguishable).
#[test]
fn dams_reaches_its_own_and_unset_but_not_missing() {
    let scope = DivisionScope::for_user(&user(&["EAM DAMS"]));
    assert_eq!(guard_decision(scope, Some(Some(DIST))), GuardOutcome::Allowed);
    assert_eq!(guard_decision(scope, Some(None)), GuardOutcome::Allowed); // unset visible to both
    assert_eq!(guard_decision(scope, None), GuardOutcome::NotFound); // truly absent
}

/// Oversight roles and users on both teams see both divisions by ID.
#[test]
fn managers_admins_and_both_teams_reach_any_division() {
    for roles in [
        &["EAM Manager", "EAM DAMS"][..], // manager overrides confinement
        &["EAM Admin", "EAM TAMS"][..],
        &["Administrator"][..],  // platform admin
        &["EAM DAMS", "EAM TAMS"][..], // both teams
        &["EAM User"][..],       // neither team → roll-out default (unrestricted)
    ] {
        let scope = DivisionScope::for_user(&user(roles));
        assert_eq!(guard_decision(scope, Some(Some(TRANS))), GuardOutcome::Allowed, "{roles:?}");
        assert_eq!(guard_decision(scope, Some(Some(DIST))), GuardOutcome::Allowed, "{roles:?}");
    }
}

/// The list path is scoped by the same rule: a DAMS user's every list/search/
/// count query carries a predicate that excludes transmission rows, so a
/// transmission record cannot surface in a list either (§6.3 "not in a list,
/// a search, a report, a dashboard count").
#[test]
fn dams_list_predicate_excludes_transmission() {
    let dams = user(&["EAM DAMS"]);
    let pred = division_predicate(&dams, "division").expect("DAMS must be scoped");
    assert!(pred.contains("distribution"));
    assert!(!pred.contains("transmission"));
    // Unset rows remain visible so unclassified records are never lost.
    assert!(pred.contains("IS NULL"));

    // Oversight roles get no predicate (unrestricted).
    assert_eq!(division_predicate(&user(&["EAM Manager"]), "division"), None);
}
