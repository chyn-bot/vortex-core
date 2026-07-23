//! Identity federation for Vortex Core.
//!
//! Vortex identity was local-only (argon2id + TOTP MFA); the README's "LDAP
//! federation" claim was aspirational. This module makes federation real,
//! starting with **OIDC** (OpenID Connect) — the protocol Azure AD/Entra,
//! Okta, Google Workspace, and Keycloak all speak — with SAML and LDAP able to
//! reuse the same per-tenant `identity_provider` / `user_federated_identity`
//! tables (migration 167).
//!
//! Design choices (confirmed with the operator):
//! * **OIDC first**, authorization-code flow, RS256 ID tokens.
//! * **JIT provisioning + link by verified email**: a first federated login
//!   auto-creates or links a local user, keyed on the IdP `sub` (never on raw
//!   email, which is spoofable) recorded in `user_federated_identity`.
//!
//! The HTTP flow lives here; the session it produces is minted by the host's
//! existing `issue_web_session`, so federated and password logins converge on
//! one audited, cap-enforced session path.

pub mod oidc;

pub use oidc::{
    authorize_url, discover, exchange_code, sign_state, validate_id_token, verify_state,
    Discovery, OidcClaims, OidcConfig, StateData,
};
