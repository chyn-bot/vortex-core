# Vortex Project Instructions

## Project Context

Vortex is a Rust-based EAM (Enterprise Asset Management) core targeting Malaysian electrical utilities. This is critical infrastructure software serving national power grid operations.

## Compliance Requirements (Non-Negotiable)

This system must meet standards equivalent to:

- **NERC CIP** (Critical Infrastructure Protection)
- **Suruhanjaya Tenaga** (Malaysian Energy Commission)
- **NACSA** cybersecurity requirements

### Required Compliance Features

1. **Immutable Audit Ledger (WORM)**
- Append-only audit log with cryptographic chaining
- DB-level restrictions preventing UPDATE/DELETE
- All critical operations must be logged
1. **Electronic Signatures (eSig)**
- Dual password verification for critical operations
- Cryptographic signatures on approvals
- Cannot bypass approval workflows
1. **LDAP/AD Federation**
- Real-time user sync (not polling)
- User deactivation within 24 hours of termination
- Access revocation must be immediate
1. **Asset Baseline & Drift Detection**
- Configuration snapshots with hash verification
- Automatic variance detection and alerting
- Change requires approved Change Request
1. **Hierarchical Asset Graph**
- Parent-child relationships with proper cascade rules
- Criticality inheritance (Low/Medium/High impact)
- Orphan handling on parent deletion
1. **Multi-Level Approval Workflows**
- State machine for approvals
- Role-based approval requirements
- eSig required for High criticality assets

## Architecture Rules

### Workspace Structure

Vortex uses Cargo workspaces. Each domain is a separate crate:

```
vortex/
├── crates/
│   ├── vortex-core/        # Shared types, traits (minimal, stable)
│   ├── vortex-db/          # Database layer
│   ├── vortex-audit/       # WORM audit ledger
│   ├── vortex-auth/        # LDAP, eSig, RBAC
│   ├── vortex-workflow/    # Approval state machines
│   ├── vortex-asset/       # Asset management
│   ├── vortex-workorder/   # Work orders
│   └── vortex-compliance/  # Drift detection
├── bins/
│   ├── vortex-cli/         # Thin CLI shell
│   └── vortex-api/         # REST/GraphQL server
└── plugins/                # Dynamic plugins
```

### Compilation Rules

**CRITICAL: Avoid designs requiring full recompilation**

- Each crate compiles independently
- Plugins should NOT require rebuilding the CLI
- Use feature flags for optional modules
- Consider dylib loading for hot-reload during dev

When adding new functionality:

1. Create a new crate if it's a distinct domain
1. Depend only on `vortex-core` and necessary crates
1. Never create circular dependencies
1. CLI/API bins are thin shells that compose crates

### Security Rules

1. **Safe Deserialization Only**
- Use `serde` with explicit types
- Never deserialize untrusted data into arbitrary types
- No pickle-equivalent patterns
1. **Supply Chain Verification**
- Run `cargo audit` before adding dependencies
- Minimize dependency count
- Pin versions in workspace Cargo.toml
1. **Cryptographic Operations**
- Use `ring` crate for crypto
- Sign critical operations
- Hash baselines with SHA-256
1. **No Unsafe Code** (without explicit justification)
- Unsafe blocks require comments explaining why
- Prefer safe abstractions

## Code Style

### Error Handling

```rust
// Use thiserror for library errors
#[derive(Debug, thiserror::Error)]
pub enum AssetError {
    #[error("Asset not found: {0}")]
    NotFound(AssetId),
    #[error("Baseline drift detected")]
    DriftDetected(Vec<Variance>),
}

// Propagate with ?
pub async fn get_asset(id: AssetId) -> Result<Asset, AssetError> {
    // ...
}
```

### IDs

Use strongly-typed IDs, not raw UUIDs:

```rust
// Good
pub fn get_asset(id: AssetId) -> Result<Asset, Error>;

// Bad
pub fn get_asset(id: Uuid) -> Result<Asset, Error>;
```

### Audit Logging

Every state-changing operation must log to audit:

```rust
// Good
async fn approve_workorder(id: WorkOrderId, user: UserId) -> Result<()> {
    let wo = get_workorder(id).await?;
    wo.approve(user).await?;

    audit.append(AuditEntry {
        action: AuditAction::WorkOrderStatusChanged {
            from: "pending",
            to: "approved"
        },
        actor: user.into(),
        resource: id.into(),
        // ...
    }).await?;

    Ok(())
}
```

## Testing Requirements

- Unit tests for all business logic
- Integration tests for approval workflows
- Audit ledger integrity tests
- LDAP sync edge cases (user termination timing)

## Malaysian Regulatory Context

- Currency: Malaysian Ringgit (MYR)
- Timezone: Asia/Kuala_Lumpur (UTC+8)
- Date format: DD/MM/YYYY for display
- Regulatory body: Suruhanjaya Tenaga (Energy Commission)

## What NOT To Do

1. Don't bypass approval workflows for "convenience"
1. Don't allow audit log modification
1. Don't use polling for LDAP sync (use real-time)
1. Don't store passwords in plain text
1. Don't create monolithic binaries that require full recompile
1. Don't skip audit logging for "internal" operations
1. Don't allow asset baseline changes without Change Request
