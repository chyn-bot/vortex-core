//! DAMS / TAMS division boundary enforcement (spec §6.3).
//!
//! Distribution (DAMS) and transmission (TAMS) are run by two teams that must
//! not see each other's assets or work — "not in a list, a search, a report, a
//! dashboard count, or by addressing its ID directly." This module is the
//! single source of that boundary: every read path derives a [`DivisionScope`]
//! from the caller and either
//!
//!  * appends [`DivisionScope::sql_predicate`] to its query (lists, searches,
//!    and every *elevated* aggregate that bypasses per-row checks), or
//!  * calls [`DivisionScope::allows`] before returning a single fetched record
//!    (fetch-by-id must **403, not empty**).
//!
//! ## The rules (§6.3)
//!
//! | Principal | Scope |
//! |---|---|
//! | Manager / Admin / platform admin | Unrestricted (oversight & consolidated reporting) |
//! | DAMS only | `division ∈ {distribution, unset}` |
//! | TAMS only | `division ∈ {transmission, unset}` |
//! | Both DAMS and TAMS | Unrestricted (sees both) |
//! | Neither | Unrestricted (roll-out default, §6.3) |
//!
//! `unset` (a NULL `division`) is always in scope, so an unclassified record is
//! never silently lost. The roll-out default (neither-group = unrestricted) lets
//! the boundary be turned on team-by-team; a deploy that prefers deny-by-default
//! assigns every user a division first.

use vortex_plugin_sdk::prelude::*;

/// Stored `division` values (see migration 009). `unset` is modelled as NULL.
pub const DIST: &str = "distribution";
pub const TRANS: &str = "transmission";

const ROLE_DAMS: &str = "EAM DAMS";
const ROLE_TAMS: &str = "EAM TAMS";
const ROLE_MANAGER: &str = "EAM Manager";
const ROLE_ADMIN: &str = "EAM Admin";

/// The set of divisions a principal may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DivisionScope {
    /// No row-level restriction. Manager/Admin, platform admins, users in
    /// *both* teams, and users in *neither* team (the roll-out default).
    Unrestricted,
    /// Confined to a single division. `unset` (NULL) rows remain visible.
    Only(&'static str),
}

impl DivisionScope {
    /// Resolve the caller's scope from their role claims (§6.1/§6.3).
    pub fn for_user(user: &AuthUser) -> Self {
        // Oversight roles and platform admins always see both divisions, even
        // when also assigned to one, for consolidated reporting.
        if user.is_admin() || user.has_role(ROLE_MANAGER) || user.has_role(ROLE_ADMIN) {
            return DivisionScope::Unrestricted;
        }
        match (user.has_role(ROLE_DAMS), user.has_role(ROLE_TAMS)) {
            (true, true) => DivisionScope::Unrestricted, // both teams → both divisions
            (true, false) => DivisionScope::Only(DIST),
            (false, true) => DivisionScope::Only(TRANS),
            (false, false) => DivisionScope::Unrestricted, // neither → roll-out default
        }
    }

    /// A SQL predicate to `AND` into a query, scoping the column `col`
    /// (e.g. `"division"` or a table-qualified `"m.division"`) to the caller.
    /// Returns `None` when unrestricted.
    ///
    /// **Injection-safe:** the only interpolated value is one of two
    /// compile-time constants (`DIST`/`TRANS`), never request input; `col` is an
    /// author-controlled identifier supplied at the call site, never user input.
    /// Unset (NULL) rows always pass.
    pub fn sql_predicate(&self, col: &str) -> Option<String> {
        match self {
            DivisionScope::Unrestricted => None,
            DivisionScope::Only(d) => Some(format!("({col} IS NULL OR {col} = '{d}')")),
        }
    }

    /// Does a single record's stored `division` fall within scope? Gate every
    /// fetch-by-id with this: a cross-division record must return 403, not an
    /// empty/not-found result (§6.3).
    pub fn allows(&self, record_division: Option<&str>) -> bool {
        match self {
            DivisionScope::Unrestricted => true,
            // `unset` is visible to both teams; otherwise it must match exactly.
            DivisionScope::Only(d) => match record_division {
                None => true,
                Some(rd) => rd == *d,
            },
        }
    }
}

/// Convenience: the caller's scoped SQL predicate for `col`, or `None`.
pub fn division_predicate(user: &AuthUser, col: &str) -> Option<String> {
    DivisionScope::for_user(user).sql_predicate(col)
}

/// Append the caller's division predicate to a `WHERE` fragment already under
/// construction. `existing` is the accumulated clause *without* a leading
/// `WHERE`/`AND`; returns it with the scope AND-ed on (or unchanged if the
/// caller is unrestricted). Handy for the hand-written elevated reads
/// (dashboards, live map) that §6.3 requires to re-apply the filter.
pub fn and_scope(user: &AuthUser, col: &str, existing: &str) -> String {
    match division_predicate(user, col) {
        None => existing.to_string(),
        Some(pred) if existing.trim().is_empty() => pred,
        Some(pred) => format!("{existing} AND {pred}"),
    }
}

/// The outcome of gating a fetch-by-id, before it is turned into an HTTP
/// response. Kept separate from the DB lookup so the security decision — in
/// particular "cross-division ⇒ Forbidden, **never** a silent NotFound" — is
/// unit-testable without a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardOutcome {
    /// In scope — proceed.
    Allowed,
    /// Row exists but is in another division — must 403 (§6.3).
    Forbidden,
    /// Row genuinely absent — 404.
    NotFound,
}

/// Pure decision for [`guard_division`]. `row` is the lookup result:
/// `None` = no such row; `Some(div)` = row present with this `division`
/// (`div = None` means the row's division is unset/NULL).
pub fn guard_decision(scope: DivisionScope, row: Option<Option<&str>>) -> GuardOutcome {
    match row {
        None => GuardOutcome::NotFound,
        Some(div) => {
            if scope.allows(div) {
                GuardOutcome::Allowed
            } else {
                // Exists but out of division: a cross-division fetch must fail
                // as Forbidden, not as an empty/NotFound that hides the reason.
                GuardOutcome::Forbidden
            }
        }
    }
}

/// Gate a fetch-by-id: verify the caller may reach the row `id` in `table`.
///
/// Returns `Ok(())` when in scope, or an error `Response` to return verbatim:
/// **403 Forbidden** for a cross-division row (never an empty/404 that would
/// leak the row's existence pattern differently — §6.3), or 404 when the row
/// genuinely does not exist. Unrestricted callers skip the lookup entirely.
///
/// `table` is an author-supplied literal at every call site (never request
/// input), so interpolating it is safe.
pub async fn guard_division(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    user: &AuthUser,
    table: &str,
    id: vortex_plugin_sdk::uuid::Uuid,
) -> Result<(), Response> {
    let scope = DivisionScope::for_user(user);
    if matches!(scope, DivisionScope::Unrestricted) {
        return Ok(());
    }
    let sql = format!("SELECT division FROM {table} WHERE id = $1");
    let row: Option<Option<String>> = vortex_plugin_sdk::sqlx::query_scalar::<_, Option<String>>(&sql)
        .bind(id)
        .fetch_optional(db)
        .await
        .unwrap_or(None);
    match guard_decision(scope, row.as_ref().map(|d| d.as_deref())) {
        GuardOutcome::Allowed => Ok(()),
        GuardOutcome::Forbidden => Err((StatusCode::FORBIDDEN, "Forbidden").into_response()),
        GuardOutcome::NotFound => Err((StatusCode::NOT_FOUND, "Not found").into_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vortex_plugin_sdk::uuid::Uuid;

    fn user_with(roles: &[&str]) -> AuthUser {
        AuthUser {
            id: Uuid::nil(),
            username: "t".into(),
            full_name: None,
            session_id: Uuid::nil(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
            contact_id: None,
            is_portal: false,
        }
    }

    #[test]
    fn dams_only_is_confined_to_distribution() {
        let s = DivisionScope::for_user(&user_with(&["EAM User", "EAM DAMS"]));
        assert_eq!(s, DivisionScope::Only(DIST));
        assert_eq!(
            s.sql_predicate("division").as_deref(),
            Some("(division IS NULL OR division = 'distribution')")
        );
        assert!(s.allows(Some("distribution")));
        assert!(s.allows(None)); // unset visible to both
        assert!(!s.allows(Some("transmission"))); // the hard boundary
    }

    #[test]
    fn tams_only_is_confined_to_transmission() {
        let s = DivisionScope::for_user(&user_with(&["EAM User", "EAM TAMS"]));
        assert_eq!(s, DivisionScope::Only(TRANS));
        assert!(s.allows(Some("transmission")));
        assert!(!s.allows(Some("distribution")));
    }

    #[test]
    fn both_teams_see_both_divisions() {
        let s = DivisionScope::for_user(&user_with(&["EAM DAMS", "EAM TAMS"]));
        assert_eq!(s, DivisionScope::Unrestricted);
        assert!(s.allows(Some("transmission")) && s.allows(Some("distribution")));
        assert_eq!(s.sql_predicate("division"), None);
    }

    #[test]
    fn neither_team_is_unrestricted_rollout_default() {
        let s = DivisionScope::for_user(&user_with(&["EAM User"]));
        assert_eq!(s, DivisionScope::Unrestricted);
    }

    #[test]
    fn manager_and_admin_override_division_confinement() {
        // A manager who is *also* only on the DAMS team still sees both.
        let mgr = DivisionScope::for_user(&user_with(&["EAM Manager", "EAM DAMS"]));
        assert_eq!(mgr, DivisionScope::Unrestricted);
        let adm = DivisionScope::for_user(&user_with(&["EAM Admin", "EAM TAMS"]));
        assert_eq!(adm, DivisionScope::Unrestricted);
    }

    #[test]
    fn platform_admin_is_unrestricted() {
        let s = DivisionScope::for_user(&user_with(&["Administrator", "EAM TAMS"]));
        assert_eq!(s, DivisionScope::Unrestricted);
    }

    #[test]
    fn predicate_respects_column_alias() {
        let s = DivisionScope::Only(DIST);
        assert_eq!(
            s.sql_predicate("m.division").as_deref(),
            Some("(m.division IS NULL OR m.division = 'distribution')")
        );
    }

    #[test]
    fn and_scope_composes_with_existing_where() {
        let dams = user_with(&["EAM DAMS"]);
        assert_eq!(
            and_scope(&dams, "division", "active = true"),
            "active = true AND (division IS NULL OR division = 'distribution')"
        );
        assert_eq!(and_scope(&dams, "division", ""),
            "(division IS NULL OR division = 'distribution')");
        // Unrestricted leaves the clause untouched.
        let mgr = user_with(&["EAM Manager"]);
        assert_eq!(and_scope(&mgr, "division", "active = true"), "active = true");
    }
}
