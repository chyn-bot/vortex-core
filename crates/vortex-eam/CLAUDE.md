# Vortex EAM — Utilities Vertical

## What this crate is

`vortex-eam` is the **utilities vertical plugin** for Vortex. It implements Enterprise Asset Management for electrical power utilities — substations, transmission lines, transformers, switchgear, condition monitoring, maintenance workflows — on top of the generic Vortex core.

This crate is a `Plugin` in the Vortex platform sense: see [`crates/vortex-framework/src/plugin.rs`](../vortex-framework/src/plugin.rs) for the trait, and [`../../docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) for the platform-vs-vertical contract.

> Scope boundary: anything that assumes "electrical utility" or "Malaysia" lives here. If you find yourself wanting to add general-purpose ERP capability (contacts, currencies, scheduling, audit, policy), it belongs in core, not here.

## Target users

Utility engineers and field technicians — not general office users. Design for:
- Substation / field conditions (poor connectivity, gloves, sunlight-readable screens).
- Technical vocabulary — "bay", "feeder", "DGA", "Duval triangle", "partial discharge" — used directly, not dumbed down.
- Auditability over convenience. Utility staff will accept an extra click if it keeps them out of a regulator's crosshairs.

## Compliance context (vertical-specific)

This vertical must support customers who answer to:

- **NERC CIP** — North American Critical Infrastructure Protection (reference standard even for non-NERC customers).
- **Suruhanjaya Tenaga** — Malaysian Energy Commission.
- **NACSA** — Malaysian National Cyber Security Agency.

These are **vertical compliance profiles**. Core provides the primitives (WORM audit ledger, Ed25519 signing, Cedar policy engine, eSig workflow primitives, LDAP federation hooks); this plugin configures them into the specific shape the utility regulators expect.

### Required capabilities for utility compliance

1. **Immutable audit ledger (WORM)** — already provided by `vortex-security::AuditLog`. This plugin must emit audit events for every asset state change, work-order transition, and inspection approval.
2. **Electronic signatures (eSig)** — dual-password verification on approvals for High-criticality assets. Cannot be bypassed.
3. **LDAP/AD federation** — real-time sync (not polling). User deactivation propagates within 24 hours of termination; access revocation is immediate.
4. **Asset baseline & drift detection** — configuration snapshots with hash verification. Variance triggers an alert and requires an approved Change Request (uses `vortex-change` plugin).
5. **Hierarchical asset graph** — 8 levels, parent-child with criticality inheritance and orphan handling (see `models/hierarchy.rs`).
6. **Multi-level approval workflows** — via `vortex-workflow::StateMachine`. eSig required for High criticality.

## Domain model

### 8-level asset hierarchy

```
Region (L0)     — Transmission / Distribution division
└── Site (L1)   — Physical location
    └── Substation (L2) — Electrical infrastructure
        └── Bay (L3)    — Feeder, transformer, bus coupler
            └── Asset (L4)       — Equipment instance
                └── Component (L5)
                    └── Part (L6-7)  — Replaceable parts, with sub-parts
```

See `src/models/hierarchy.rs`. Region/Site/Substation/Bay are in the vertical; the generic "org unit" concept in core is different and should not be conflated.

### Equipment types covered

Power transformers (with DGA), switchgear / circuit breakers, ring main units, current/voltage/capacitive voltage transformers, surge arresters, cables, busbars, isolators, earthing systems, protection systems, SCADA systems, battery banks. See `src/models/equipment.rs`.

### Condition monitoring

- Dissolved Gas Analysis with Duval Triangle classification (`services/dga.rs`)
- Oil quality tests
- Thermal imaging
- Partial discharge
- Insulation resistance
- SF6 analysis, contact timing, battery discharge

Plus a generic `ConditionMonitoringRecord` and a composite `AssetHealthIndex`. See `src/models/condition.rs`.

### Work orders and inspections

- `WorkOrderStateMachine`: draft → scheduled → in_progress → completed (with cancel / hold branches). Implemented as a `vortex-workflow::StateMachine` so transitions flow through the generic engine with audit + policy gating for free.
- `InspectionResult` has its own approval workflow.
- Checklist scoring: weighted average with critical-failure override (`services/checklist.rs`).

## Malaysian regulatory context

Applies only to Malaysian customers; this is locale, not platform.

- **Currency**: Malaysian Ringgit (MYR)
- **Timezone**: Asia/Kuala_Lumpur (UTC+8)
- **Date format**: DD/MM/YYYY for display
- **Regulatory body**: Suruhanjaya Tenaga
- **Reference customer**: SESB (Sabah Electricity Sdn Bhd); current source of feature parity requirements. The legacy Odoo/Remicle18 module under `/home/vortex/data/sesb_eam` is the specification to match, not code to copy.

## Sequences

Equipment codes, maintenance codes, inspection codes, etc. are generated by atomic UPSERT on the `eam_sequences` table. Types: EQP, CMP, PRT, MNT, INS, MP, TL, TWR, CM.

> Note: sequence generation is a *platform* primitive every vertical needs. This implementation is a candidate to promote to core. Until then, other plugins needing sequences should either depend on this crate or re-implement.

## Single-Line Diagram (SLD) UI

Vanilla JS `VComponent` mini-framework — event delegation, `setState → render`. No React, no build step, CSP-compliant. Lives under the UI shell served by `vortex-server`.

## Security hardening notes (applied 2026-02-06)

- `validate_identifier()` for all dynamic SQL table/column names.
- LIKE search escapes `%`, `_`, `\`.
- Work order transitions parameterized.
- DB values HTML-escaped in Askama templates.
- Login rate limiter.
- Security headers middleware.
- `Secure` + `SameSite=Strict` cookies.

## Portal and Wizard APIs

- **Portal API** at `/api/eam/portal/*` — field-technician endpoints: maintenance list/detail/action/save, checklist save, equipment list/lookup/detail/request-maintenance/qr.
- **Wizard API** at `/api/eam/wizards/*` — batch maintenance creation, transactional hierarchy creation.

These use the plugin's `nested_services` mount point because they carry their own per-request DB context.

## Testing requirements

- Unit tests for DGA classification, Duval triangle edge cases, health-index scoring, checklist weighted-average with critical-failure override.
- Integration tests for work-order state-machine transitions including reject/cancel/hold paths.
- Audit-chain integration: every state-changing handler must produce a verifiable audit entry.
- eSig approval tests for High-criticality assets.

## What NOT to do in this crate

1. Don't bypass approval workflows "for convenience" on High-criticality assets — regulators will look for exactly this.
2. Don't add general-purpose ERP features here (contacts, currencies, taxes, mail, policy engine). Push upstream into core or a new core crate.
3. Don't invent parallel audit / policy / workflow paths — always use the core primitives.
4. Don't let UI convenience override field ergonomics. A technician in the sun with gloves on is the user.
5. Don't poll LDAP; use real-time federation hooks from core.
6. Don't hardcode Malaysia-specific values (currency, timezone, date format) — use locale settings so the same plugin can serve utilities in other jurisdictions.
