# Vortex Core

## What Vortex is

Vortex is a **horizontal ERP platform** written in Rust. It provides the kernel — persistence, identity, audit, policy, workflow, multi-tenancy, plugin loading, HTTP shell — and everything domain-specific ships as a **plugin crate**.

Utilities (`vortex-eam`) is the first vertical. More will follow (manufacturing, retail, services, finance, etc.). Any feature that assumes a specific industry, regulator, or geography does **not** belong in core.

> See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full platform contract: what core guarantees, what plugins provide, the `Plugin` trait, migration ownership, and deployment shapes.

## Scope rules (read before adding code)

**In core**:
- Things every vertical needs: users, companies/tenants, roles, partners/contacts, sessions, audit, policy, workflow engine, ORM, sequences, mail/notification bus, module registry, multi-DB manager, i18n primitives, scheduled actions, reporting.
- Compliance *primitives* — WORM audit, eSig, cryptographic chaining — are core because they're reusable across regulated verticals.

**In a plugin crate**:
- Industry-specific models and workflows (assets, leads, invoices, manufacturing orders, patient records, …).
- Vertical compliance *profiles* (NERC-CIP for utilities, SOX for finance, HIPAA for healthcare) — configured on top of the core primitives, not baked into them.
- Anything that names a specific regulator, currency, geography, or industry.

**Rule of thumb**: if you can imagine two different verticals wanting the feature, it's probably core. If the feature only makes sense inside one vertical, it's a plugin.

## Workspace layout

```
vortex-core/
├── crates/
│   ├── vortex-common/      # shared types, errors, results
│   ├── vortex-macros/      # proc-macros (#[derive(Model)], etc.)
│   ├── vortex-orm/         # ORM, connection pool, model trait, sequence service
│   ├── vortex-security/    # WORM audit ledger, crypto, signing, chain verifier
│   ├── vortex-policy/      # Cedar ABAC policy engine
│   ├── vortex-workflow/    # Generic state-machine workflow engine
│   ├── vortex-module/      # Module manifest, loader, installed-module registry
│   ├── vortex-framework/   # AppState, Plugin trait, menu, sidebar, scheduler
│   ├── vortex-chatter/     # Mail / notification bus
│   ├── vortex-server/      # HTTP shell, middleware, shared handlers
│   ├── vortex-cli/         # Thin host binary (vortex command)
│   │
│   ├── vortex-eam/         # VERTICAL PLUGIN — utilities / EAM
│   │   └── migrations/     # Plugin-owned schema (applied via Plugin::migrations)
│   └── vortex-change/      # VERTICAL PLUGIN — change requests
│       └── migrations/
├── migrations/             # Core migrations only
└── docs/
    └── ARCHITECTURE.md     # Platform vs vertical contract
```

> Core migrations live in `vortex-core/migrations/`. Plugin migrations live inside the plugin crate and are applied via `Plugin::migrations()` using `include_str!` — see `vortex-framework::PluginMigration` for the contract. **Never** put plugin-specific schema into the core `migrations/` directory.

## Compilation rules

- Each crate compiles independently. Plugins depend on `vortex-framework` and whatever core crates they need — **never** on `vortex-cli` or `vortex-server`.
- Adding a new vertical means: new crate under `crates/`, implement `Plugin`, add to workspace members, register in the host's plugin list. No core changes required for typical features.
- Avoid circular dependencies. If you find yourself needing one, the abstraction probably belongs one layer up in `vortex-framework` or `vortex-common`.
- `AppState` is the stable cross-crate contract. Adding a field is a workspace recompile; removing one breaks every plugin. Treat it like an ABI.

## Security rules (platform-wide)

1. **Safe deserialization only** — explicit serde types, never arbitrary.
2. **Supply chain** — `cargo audit` clean before adding any dep. Pin versions in workspace `Cargo.toml`.
3. **Crypto** — `ring` for primitives. Sign critical operations. Hash baselines with SHA-256.
4. **No `unsafe`** without a comment explaining why.
5. **Audit everything state-changing** — via `state.audit.log()`, never raw INSERTs into `audit_log` (the WORM chain would break).
6. **Policy-gate everything user-facing** — via `state.policy.check(...)` from Cedar.
7. **OWASP basics** — parameterized SQL, `validate_identifier()` for dynamic table/column names, HTML-escape DB values in templates, rate-limit auth endpoints, security headers middleware, `Secure` + `SameSite=Strict` cookies.

## Code style

### Error handling

`thiserror` for library errors, `anyhow` for binaries. Propagate with `?`.

```rust
#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    #[error("instance not found: {0}")]
    NotFound(Uuid),
    #[error("illegal transition from {from} to {to}")]
    IllegalTransition { from: String, to: String },
}
```

### IDs

Prefer strongly-typed ID newtypes over raw `Uuid` in public APIs.

### Audit logging

Every state-changing operation must call `state.audit.log(...)`. Plugins get the `AuditLog` via `AppState`. Direct SQL inserts into `audit_log` are forbidden — they break the hash chain and fail verification.

### Policy checks

Every user-initiated action must go through `state.policy.check(...)`. The Cedar engine is loaded from DB-backed policies on startup; plugins register their entity types and action schemas in `on_startup`.

## Testing requirements

- Unit tests for all business logic in their owning crate.
- Integration tests for anything that touches the audit chain (WORM integrity), the policy engine, or the workflow engine.
- Plugins test in isolation against the core crates, not against the host binary.

## What NOT to do

1. Don't put industry-specific logic in core crates (`vortex-*` other than plugin crates).
2. Don't bypass audit or policy for "internal" operations — if it changes state, it goes through the ledger and the gate.
3. Don't reach into plugin crates from core. Core never knows which plugins exist at compile time.
4. Don't store passwords in plain text, skip hashing, or use polling where event-driven is possible.
5. Don't design anything that requires the full workspace to recompile to ship a vertical feature.
6. Don't make `AppState` churn — it's the platform ABI.

## For vertical-specific context

Each plugin crate has its own `CLAUDE.md`:
- Utilities / EAM compliance and domain context: [`crates/vortex-eam/CLAUDE.md`](crates/vortex-eam/CLAUDE.md)
- Change requests: `crates/vortex-change/CLAUDE.md` *(TODO)*

If you are working inside a plugin crate, read that plugin's CLAUDE.md first for domain vocabulary and compliance requirements. If you are working in a core crate, this file is the source of truth.
